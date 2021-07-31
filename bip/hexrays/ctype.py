from .astnode import HxCType, ASSIGNMENTS, COMPARISONS, BIN_OPS, PRE_OPS, POST_OPS, UNARY_OPS, OPS, LITERALS, EXPRESSIONS, LOOPS, STATEMENTS
from bip.base.biptype import BipType
from bip.base.bipelt import GetElt
import idaapi
import ida_bytes
import idc


#: Used in :meth:`CType._validate_params`, do not modify this or rely
#: on this in any way. Param names grouped together are mutually exlusive.
_known_params = {
    HxCType.COT_NUM: { ( 'value', ): 'Value to check against (can be iterable)', },
    HxCType.COT_FNUM: { ( 'value', ): 'Value to check against (can be iterable)', },
    HxCType.COT_STR: { ( 'value', ): 'Value to check against (can be iterable)', },
    HxCType.COT_OBJ: { 
        ( 'value', ): 'Value to check against (can be iterable)',
        ( 'ea', ) : 'Address to check against (can be iterable)',
        ( 'name', ): 'Name to check against (can be iterable)', },
    HxCType.COT_VAR: {
        ( 'is_arg', 'is_var' ): 'Only matches variable/arguments',
        ( 'name', ): 'Variable name to match against (can be iterable)',
        ( 'index', ): 'Variable index to match against (can be iterable)', },
}

_ANY_NODE_TYPE_ID = -1
_EITHER_NODE_TYPE_ID = -2
_CONTAINS_NODE_TYPE_ID = -3

_ASSIGNMENT_NODE_TYPE_ID = -4
_COMPARISON_NODE_TYPE_ID = -5
_BIN_OP_NODE_TYPE_ID = -6
_PRE_OP_NODE_TYPE_ID = -7
_POST_OP_NODE_TYPE_ID = -8
_UNARY_OP_NODE_TYPE_ID = -9
_OP_NODE_TYPE_ID = -10
_LITERAL_NODE_TYPE_ID = -11
_EXPR_NODE_TYPE_ID = -12
_LOOP_NODE_TYPE_ID = -13
_STMT_NODE_TYPE_ID = -14

_NODE_CATEGORIES = {
    _ASSIGNMENT_NODE_TYPE_ID: ASSIGNMENTS,
    _COMPARISON_NODE_TYPE_ID: COMPARISONS,
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

for _expr in EXPRESSIONS | {_ASSIGNMENT_NODE_TYPE_ID,
                            _COMPARISON_NODE_TYPE_ID,
                            _BIN_OP_NODE_TYPE_ID,
                            _PRE_OP_NODE_TYPE_ID,
                            _POST_OP_NODE_TYPE_ID,
                            _UNARY_OP_NODE_TYPE_ID,
                            _OP_NODE_TYPE_ID,
                            _LITERAL_NODE_TYPE_ID,
                            _EXPR_NODE_TYPE_ID,}:
    if _expr not in _known_params:
        _known_params[_expr] = dict()
    _known_params[_expr].update({ ( 'type', ): 
                                    'Expression type to match against, either :class:`~bip.base.BipType` ' \
                                    'or anything that its constructor accepts (can be iterable)', })


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
            expected = self._params['type']
            found = False
            if not isinstance(expected, str):
                try:
                    found |= other.type in expected # assume iterable of types
                except TypeError:
                    found |= BipType.make(expected) != other.type
            else:
                found |= BipType.make(expected) != other.type

            if not found:
                return False

        if self.node_type_id in (HxCType.COT_NUM, HxCType.COT_FNUM, HxCType.COT_STR):
            expected = self._params['value']
            try:
                return other.value in expected # assume iterable of values
            except TypeError:
                return expected == other.value
        elif self.node_type_id == HxCType.COT_OBJ:
            ea = other.value
            found = False
            if 'ea' in self._params:
                expected = self._params['ea']
                try:
                    found |= ea in expected # assume iterable of ea
                except TypeError:
                    found |= self._params['ea'] == ea

            if 'name' in self._params:
                expected = self._params['name']
                if isinstance(expected, str):
                    found |= expected == idaapi.get_name(ea)
                else:
                    found |= idaapi.get_name(ea) in expected # assume iterable of names

            if 'value' in self._params:
                expected_value = self._params['value']
                elt = GetElt(ea)
                if hasattr(elt, 'value'): # some objs do not have a value property
                    actual_value = elt.value
                    if isinstance(expected_value, str): # comparison is made with bytes
                        expected_value = expected_value.encode()

                    try:
                        if isinstance(expected_value, bytes):
                            found |= expected_value == actual_value
                        else:
                            found |= actual_value in expected_value # assume iterable of values
                            if not found: # in case the value was not found, check if the value
                                          # was passed as a string and if so, compare with it
                                for item in expected_value:
                                    if isinstance(item, str):
                                        found |= item.encode() == actual_value
                    except TypeError:
                        found |= expected_value == actual_value

            return found 
            #: TODO: implement comparison for arrays and custom objects
        elif self.node_type_id == HxCType.COT_VAR:
            if 'is_arg' in self._params:
                if self._params['is_arg'] != other.lvar.is_arg:
                    return False
            elif 'is_var' in self._params:
                if self._params['is_var'] == other.lvar.is_arg:
                    return False

            found_variable = False
            if 'name' in self._params:
                expected = self._params['name']
                try:
                    found_variable |= other.lvar_name in expected # assume iterable of names
                except TypeError:
                    found_variable |= expected == other.lvar_name

            if 'index' in self._params:
                expected = self._params['index']
                try:
                    found_variable |= other.index in expected # assume iterable of indices
                except TypeError:
                    found_variable |= expected == other.index

            if ('name' in self._params or 'index' in self._params) and not found_variable:
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

_add_ctype('assignment', _ASSIGNMENT_NODE_TYPE_ID, 'Matches all assignment operators (=, +=...)')
_add_ctype('comparison', _COMPARISON_NODE_TYPE_ID, 'Matches all comparison operators (==, !=...)')
_add_ctype('binop', _BIN_OP_NODE_TYPE_ID, 'Matches all binary operators (+, =...)')
_add_ctype('preop', _PRE_OP_NODE_TYPE_ID, 'Matches all prefixed unary operators (`*`, ++...)')
_add_ctype('postop', _POST_OP_NODE_TYPE_ID, 'Matches all postfixed unary operators ([], ()...)')
_add_ctype('unaryop', _UNARY_OP_NODE_TYPE_ID, 'Matches all unary operators (both prefixed and postfixed)')
_add_ctype('op', _OP_NODE_TYPE_ID, 'Matches all operators (both binary and unary)')
_add_ctype('literal', _LITERAL_NODE_TYPE_ID, 'Matches all literals (numbers, objects...)')
_add_ctype('expr', _EXPR_NODE_TYPE_ID, 'Matches all expressions (not exression statement though!)')
_add_ctype('loop', _LOOP_NODE_TYPE_ID, 'Matches all loops (for, while...)')
_add_ctype('stmt', _STMT_NODE_TYPE_ID, 'Matches all statements')
