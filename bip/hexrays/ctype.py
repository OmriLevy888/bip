from .astnode import HxCType, BIN_OPS, PRE_OPS, POST_OPS, UNARY_OPS, OPS, LITERALS, EXPRESSIONS, LOOPS, STATEMENTS
from bip.base.biptype import BipType
import idaapi
import ida_bytes
import idc


#: Used in :meth:`CType._validate_params`, do not modify this or rely
#: on this in any way. Param names grouped together are mutually exlusive.
_known_params = {
    HxCType.COT_NUM: { ( 'value', ): 'Value to check against', },
    HxCType.COT_FNUM: { ( 'value', ): 'Value to check against', },
    HxCType.COT_STR: { ( 'value', ): 'Value to check against', },
    HxCType.COT_OBJ: { ('value', 'ea', 'name' ): 'Value to check against', },
    HxCType.COT_VAR: {
        ('is_arg', 'is_var'): 'Only matches variable/arguments',
        ('name', 'index'): 'Variable name/index to match against', },
}

_ANY_NODE_TYPE_ID = -1
_EITHER_NODE_TYPE_ID = -2
_CONTAINS_NODE_TYPE_ID = -3

_BIN_OP_NODE_TYPE_ID = -4
_PRE_OP_NODE_TYPE_ID = -5
_POST_OP_NODE_TYPE_ID = -6
_UNARY_OP_NODE_TYPE_ID = -7
_OP_NODE_TYPE_ID = -8
_LITERAL_NODE_TYPE_ID = -9
_EXPR_NODE_TYPE_ID = -10
_LOOP_NODE_TYPE_ID = -11
_STMT_NODE_TYPE_ID = -12

_NODE_CATEGORIES = {
    _BIN_OP_NODE_TYPE_ID: BIN_OPS,
    _PRE_OP_NODE_TYPE_ID: PRE_OPS,
    _POST_OP_NODE_TYPE_ID: POST_OPS,
    _UNARY_OP_NODE_TYPE_ID: UNARY_OPS,
    _OP_NODE_TYPE_ID: OPS,
    _LITERAL_NODE_TYPE_ID: LITERALS,
    _EXPR_NODE_TYPE_ID: EXPRESSIONS,
    _LOOP_NODE_TYPE_ID: LOOPS,
    _STMT_NODE_TYPE_ID: STATEMENTS,
}

for _expr in EXPRESSIONS | {_BIN_OP_NODE_TYPE_ID,
                            _PRE_OP_NODE_TYPE_ID,
                            _POST_OP_NODE_TYPE_ID,
                            _UNARY_OP_NODE_TYPE_ID,
                            _OP_NODE_TYPE_ID,
                            _LITERAL_NODE_TYPE_ID,
                            _EXPR_NODE_TYPE_ID,}:
    if _expr not in _known_params:
        _known_params[_expr] = dict()
    _known_params[_expr].update({ ( 'type', ): 'Expression type to match against, either :class:`~bip.base.BipType` or :class:`~str`', })


class CType:
    """
        Class for representing different constaint types for matching on AST
        nodes.
    """

    def __init__(self, node_type_name, node_type_id):
        """
            Create a new :class:`~bip.hexrays.CType`. This is not meant to be
            called directly.
        """
        self.node_type_name = node_type_name
        self.node_type_id = node_type_id


class CTypeValue:
    def __init__(self, node_type_name, node_type_id, *args, **kwargs):
        """
            Create a new :class:`~bip.hexrays.CTypeValue`. This is not meant to
            be called directly but rather using :class:`~bip.hexrays.CType`
            members being invoked. Refer to :class:`~bip.hexrays.CType` for
            argument documentation.
        """
        self.node_type_name = node_type_name
        self.node_type_id = node_type_id

        self._contains = kwargs.get('contains', None)
        if self._contains is not None:
            kwargs.pop('contains')

            if callable(self._contains):
                self._contains = self._contains()
                if self._contains.node_type_id == _CONTAINS_NODE_TYPE_ID:
                    raise ValueError('Empty contains')

            if not isinstance(self._contains, CTypeValue):
                raise ValueError('Bad value for contains')
            elif self._contains.node_type_id != _CONTAINS_NODE_TYPE_ID:
                self._contains = CType.contains(self._contains)

            if len(self._contains._children) != 1:
                raise ValueError('Contains may only have one constraint')

        self._children = list(args)
        self._params = dict()

        if self.node_type_id == _CONTAINS_NODE_TYPE_ID:
            if len(args) != 1:
                raise ValueError('Contains expected one constraint')
        elif self.node_type_id not in (_EITHER_NODE_TYPE_ID, _ANY_NODE_TYPE_ID):
            #: TODO: add checks to make sure no child is ever overriden
            #: TODO: add checks to make sure there are no excess children
            for key, value in kwargs.items():
                if key in ('op', 'lhs', 'dst', 'init', 'expr') \
                    or (key == 'cond' and node_type_id != HxCType.CIT_FOR):
                    self._insert_child(0, value)
                elif key in ('rhs', 'src', 'then', 'cond') \
                    or (key == 'body' and node_type_id != HxCType.CIT_FOR):
                    self._insert_child(1, value)
                elif key in ('else', 'step'):
                    self._insert_child(2, value)
                elif key == 'body':
                    self._insert_child(3, value)
                else:
                    self._params[key] = value
          
            self._transform_children()
            self._validate_params()

    def _insert_child(self, idx, value):
        #: padd _children with None at the end
        self._children += [None] * (idx + 1 - len(self._children))
        self._children[idx] = value

    def _transform_children(self):
        actual_children = list()
        for child in self._children:
            if callable(child):
                actual_children.append(child())
            else:
                actual_children.append(child)
        self._children = actual_children

    def _validate_params(self):
        #: make sure that only known params for this node_type have been passed
        if len(self._params) == 0:
            return

        global _known_params
        if self.node_type_id not in _known_params:
            raise ValueError('Params passed to node type that does not support params')

        expected_params = _known_params[self.node_type_id]
        params_found = list()
        for param in self._params.keys():
            for mutually_exclusive_params in expected_params:
                if param in mutually_exclusive_params:
                    for already_met in params_found:
                        if already_met in mutually_exclusive_params:
                            raise ValueError(f'Passed both "{already_met}" and "{param}" as constraints')
                    params_found.append(param)

    def _check_params(self, other):
        if len(self._params) == 0:
            return True

        if 'type' in self._params:
            bipType = self._params['type']
            if isinstance(bipType, str):
                bipType = BipType.from_c(bipType)
            elif isinstance(bipType, idaapi.tinfo_t):
                bipType = BipType.from_tinfo(bipType)

            if bipType != other.type:
                return False

        if self.node_type_id in (HxCType.COT_NUM, HxCType.COT_FNUM, HxCType.COT_STR):
            return self._params['value'] == other.value
        elif self.node_type_id == HxCType.COT_OBJ:
            ea = other.value
            if 'ea' in self._params:
                return self._params['ea'] == ea
            elif 'name' in self._params:
                return self._params['name'] == idaapi.get_name(ea)

            expected_value = self._params['value']
            flags = ida_bytes.get_full_flags(ea)
            if ida_bytes.is_byte(flags):
                return ida_bytes.get_wide_byte(ea) == expected_value
            elif ida_bytes.is_word(flags):
                return ida_bytes.get_wide_word(ea) == expected_value
            elif ida_bytes.is_dword(flags):
                return ida_bytes.get_wide_dword(ea) == expected_value
            elif ida_bytes.is_qword(flags):
                return ida_bytes.get_qword(ea) == expected_value
            elif ida_bytes.is_strlit(flags):
                return idc.get_strlit_contents(ea).decode() == expected_value
            elif isinstance(expected_value, (bytes, bytearray)):
                return idc.get_bytes(ea, len(expected_value)) == expected_value
            
            #: TODO: implement comparison for arrays and custom objects
            return False
        elif self.node_type_id == HxCType.COT_VAR:
            if 'is_arg' in self._params:
                if self._params['is_arg'] != other.lvar.is_arg:
                    return False
            elif 'is_var' in self._params:
                if self._params['is_var'] == other.lvar.is_arg:
                    return False

            if 'name' in self._params:
                if self._params['name'] != other.lvar_name:
                    return False
            elif 'index' in self._params:
                if self._params['index'] != other.index:
                    return False

            return True
        else:
            #: TODO: error/warning?
            return True

    def _validate_category(self, other):
        return other.TYPE_HANDLE in _NODE_CATEGORIES[self.node_type_id]

    def _check_contains(self, constraint, other):
        if constraint._children[0] == other:
            return True

        other_children = getattr(other, 'ops', [])
        other_children += getattr(other, 'expr_children', [])
        other_children += getattr(other, 'stmt_children', [])
        for child in other_children:
            if constraint == child:
                return True

        return False

    def __eq__(self, other):
        """
            Compare to :class:`~bip.hexrays.CNode` and base classes to check
            against constraints.

            :return: True if the node matches the constraints, False otherwise.
        """
        if isinstance(other, CTypeValue):
            return self.node_type_id == other.node_type_id
        elif hasattr(other, 'TYPE_HANDLE') and not isinstance(other, type):
            if self.node_type_id == _ANY_NODE_TYPE_ID:
                return True

            if self.node_type_id == _EITHER_NODE_TYPE_ID:
                for child in self._children:
                    if child == other:
                        return True

                return False

            if self.node_type_id == _CONTAINS_NODE_TYPE_ID:
                return self._check_contains(self, other)
            elif self._contains is not None:
                if not self._check_contains(self._contains, other):
                    return False

            if self.node_type_id in _NODE_CATEGORIES:
                if not self._validate_category(other):
                    return False
            elif self.node_type_id != other.TYPE_HANDLE:
                return False

            if not self._check_params(other):
                return False

            other_children = getattr(other, 'ops', [])
            other_children += getattr(other, 'expr_children', [])
            other_children += getattr(other, 'stmt_children', [])

            if len(self._children) > len(other_children):
                #: if there are excess children filters and they are not all
                #: None/Any matches, return False
                for child in self._children[len(other_children) + 1:]:
                    if child is None:
                        continue
                    elif isinstance(child, CTypeValue) and child.node_type_id == _ANY_NODE_TYPE_ID:
                        continue

                    return False

            for idx in range(min(len(self._children), len(other_children))):
                child = self._children[idx]
                if child is None or child.node_type_id == _ANY_NODE_TYPE_ID:
                    continue

                if child != other_children[idx]:
                    return False
            return True

        return NotImplemented

    def __ne__(self, other):
        ret = self.__eq__(other)
        if ret is NotImplemented:
            return ret
        return not ret


def _add_ctype(name, value, doc):
    def _impl(*args, **kwargs):
        return CTypeValue(name, value, *args, **kwargs)
    _impl.__doc__ = doc

    global _known_params
    if _known_params.get(value) is not None:
        _impl.__doc__ += '\n\nPossible keyword paramters:'
        for params_tuple, params_doc in _known_params[value].items():
            if len(params_tuple) == 1:
                params_str = f'``{params_tuple[0]}``'
            else:
                params_str = ', '.join(map(lambda param: f'``{param}``', params_tuple[:-1]))
                params_str = ' or '.join((params_str, f'``{params_tuple[-1]}``'))
            params_str += f': {params_doc}'
            _impl.__doc__ += f'\n\n\t\t{params_str}'

    setattr(CType, name, _impl)

for attr, value in HxCType.__dict__.items():
    if 'COT' not in attr and 'CIT' not in attr:
        continue

    _, name = attr.split('_')
    name = name.lower()

    if name in ('last', 'helper'):
        continue

    cnode_class_name = 'CNode'
    if value in EXPRESSIONS:
        cnode_class_name += 'Expr' + name[0].upper() + name[1:]
    elif value in STATEMENTS:
        cnode_class_name += 'Stmt' + name[0].upper() + name[1:]

    if name == 'do':
        cnode_class_name = 'CNodeStmtDoWhile'
    elif name == 'fnum':
        cnode_class_name = 'CNodeExprFNum'
    elif name == 'tern':
        cnode_class_name = 'CNodeExprTernary'
    doc = f'Matches instances of :class:`~bip.hexrays.cnode.{cnode_class_name}`'
    
    if name in ('while', 'for'):
        name += '_loop'
    elif name in ('if', 'continue', 'break', 'return'):
        name += '_statement'
    _add_ctype(name, value, doc)

_add_ctype('any', _ANY_NODE_TYPE_ID, 'Matches everything')
_add_ctype('either', _EITHER_NODE_TYPE_ID, 'Matches either of its children')
_add_ctype('contains', _CONTAINS_NODE_TYPE_ID, 'Matches if somewhere in the AST the constaint exists')

_add_ctype('binop', _BIN_OP_NODE_TYPE_ID, 'Matches all binary operators (+, =...)')
_add_ctype('preop', _PRE_OP_NODE_TYPE_ID, 'Matches all prefixed unary operators (`*`, ++...)')
_add_ctype('postop', _POST_OP_NODE_TYPE_ID, 'Matches all postfixed unary operators ([], ()...)')
_add_ctype('unaryop', _UNARY_OP_NODE_TYPE_ID, 'Matches all unary operators (both prefixed and postfixed)')
_add_ctype('op', _OP_NODE_TYPE_ID, 'Matches all operators (both binary and unary)')
_add_ctype('literal', _LITERAL_NODE_TYPE_ID, 'Matches all literals (numbers, objects...)')
_add_ctype('expr', _EXPR_NODE_TYPE_ID, 'Matches all expressions (not exression statement though!)')
_add_ctype('loop', _LOOP_NODE_TYPE_ID, 'Matches all loops (for, while...)')
_add_ctype('stmt', _STMT_NODE_TYPE_ID, 'Matches all statements')
