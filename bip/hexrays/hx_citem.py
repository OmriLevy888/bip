

class HxCType(object):
    """
        Enum and static methods for manipulating the C type defined by
        HexRays. This is a wrapper on top of the ``ctype_t`` enum: ``cot_*``
        are for the expresion (``cexpr_t`` in ida, :class:`HxCExpr` in bip )
        and ``cit_*`` are for the statement (``cinsn_t`` in ida,
        :class:`HxCStatement` in bip). This also include some static function
        which are wrapper which manipulate those types.

        .. todo:: static function for manipulating the enum ?

        .. todo:: delete the DONE coms

        Comment on the enum are from ``hexrays.hpp`` .
    """
    COT_EMPTY       = 0
    COT_COMMA       = 1     #: x, y                             # DONE
    COT_ASG         = 2     #: x = y                            # DONE
    COT_ASGBOR      = 3     #: x |= y                       # DONE
    COT_ASGXOR      = 4     #: x ^= y                       # DONE
    COT_ASGBAND     = 5     #: x &= y                       # DONE
    COT_ASGADD      = 6     #: x += y                       # DONE
    COT_ASGSUB      = 7     #: x -= y                       # DONE
    COT_ASGMUL      = 8     #: x *= y                       # DONE
    COT_ASGSSHR     = 9     #: x >>= y signed               # DONE
    COT_ASGUSHR     = 10    #: x >>= y unsigned             # DONE
    COT_ASGSHL      = 11    #: x <<= y                      # DONE
    COT_ASGSDIV     = 12    #: x /= y signed                # DONE
    COT_ASGUDIV     = 13    #: x /= y unsigned              # DONE
    COT_ASGSMOD     = 14    #: x %= y signed                # DONE
    COT_ASGUMOD     = 15    #: x %= y unsigned              # DONE
    COT_TERN        = 16    #: x ? y : z                    # DONE
    COT_LOR         = 17    #: x || y                       # DONE
    COT_LAND        = 18    #: x && y                       # DONE
    COT_BOR         = 19    #: x | y                        # DONE
    COT_XOR         = 20    #: x ^ y                        # DONE
    COT_BAND        = 21    #: x & y                        # DONE
    COT_EQ          = 22    #: x == y int or fpu (see EXFL_FPOP)             # DONE
    COT_NE          = 23    #: x != y int or fpu (see EXFL_FPOP)             # DONE
    COT_SGE         = 24    #: x >= y signed or fpu (see EXFL_FPOP)             # DONE
    COT_UGE         = 25    #: x >= y unsigned                                  # DONE
    COT_SLE         = 26    #: x <= y signed or fpu (see EXFL_FPOP)             # DONE
    COT_ULE         = 27    #: x <= y unsigned                                  # DONE
    COT_SGT         = 28    #: x >  y signed or fpu (see EXFL_FPOP)             # DONE
    COT_UGT         = 29    #: x >  y unsigned                                  # DONE
    COT_SLT         = 30    #: x <  y signed or fpu (see EXFL_FPOP)             # DONE
    COT_ULT         = 31    #: x <  y unsigned                                  # DONE
    COT_SSHR        = 32    #: x >> y signed                                    # DONE
    COT_USHR        = 33    #: x >> y unsigned                                  # DONE
    COT_SHL         = 34    #: x << y                                           # DONE
    COT_ADD         = 35    #: x + y                                            # DONE
    COT_SUB         = 36    #: x - y                                            # DONE
    COT_MUL         = 37    #: x * y                                            # DONE
    COT_SDIV        = 38    #: x / y signed                 # DONE
    COT_UDIV        = 39    #: x / y unsigned               # DONE
    COT_SMOD        = 40    #: x % y signed                 # DONE
    COT_UMOD        = 41    #: x % y unsigned               # DONE
    COT_FADD        = 42    #: x + y fp                     # DONE
    COT_FSUB        = 43    #: x - y fp                     # DONE
    COT_FMUL        = 44    #: x * y fp                     # DONE
    COT_FDIV        = 45    #: x / y fp                     # DONE
    COT_FNEG        = 46    #: -x fp                        # DONE
    COT_NEG         = 47    #: -x                           # DONE
    COT_CAST        = 48    #: (type)x                      # DONE
    COT_LNOT        = 49    #: !x                           # DONE
    COT_BNOT        = 50    #: ~x                           # DONE
    COT_PTR         = 51    #: *x, access size in 'ptrsize' # DONE
    COT_REF         = 52    #: &x                           # DONE
    COT_POSTINC     = 53    #: x++                          # DONE
    COT_POSTDEC     = 54    #: x--                          # DONE
    COT_PREINC      = 55    #: ++x                          # DONE
    COT_PREDEC      = 56    #: --x                          # DONE
    COT_CALL        = 57    #: x(...)                       # DONE
    COT_IDX         = 58    #: x[y]                         # DONE
    COT_MEMREF      = 59    #: x.m                          # DONE
    COT_MEMPTR      = 60    #: x->m, access size in 'ptrsize'   # DONE
    COT_NUM         = 61    #: n                                # DONE # TODO mother class
    COT_FNUM        = 62    #: fpc                              # DONE # TODO mother class
    COT_STR         = 63    #: string constant                  # DONE # TODO mother class
    COT_OBJ         = 64    #: obj_ea                           # DONE # TODO mother class
    COT_VAR         = 65    #: v                                # DONE # TODO mother class
    COT_INSN        = 66    #: instruction in expression, internal representation only # DONE
    COT_SIZEOF      = 67    #: sizeof(x)                # DONE
    COT_HELPER      = 68    #: arbitrary name           # DONE
    COT_TYPE        = 69    #: arbitrary type           # DONE
    COT_LAST        = 69    #: All before this are ``cexpr_t`` after are ``cinsn_t``
    CIT_EMPTY       = 70    #: instruction types start here
    CIT_BLOCK       = 71    #: block-statement: { ... }
    CIT_EXPR        = 72    #: expression-statement: expr;
    CIT_IF          = 73    #: if-statement
    CIT_FOR         = 74    #: for-statement
    CIT_WHILE       = 75    #: while-statement
    CIT_DO          = 76    #: do-statement
    CIT_SWITCH      = 77    #: switch-statement
    CIT_BREAK       = 78    #: break-statement
    CIT_CONTINUE    = 79    #: continue-statement
    CIT_RETURN      = 80    #: return-statement
    CIT_GOTO        = 81    #: goto-statement
    CIT_ASM         = 82    #: asm-statement
    CIT_END         = 83

class HxCItem(object):
    """
        Abstract class representing both C expression and C statement as
        defined by HexRays.

        An object of this class should never be created. The
        :func:`GetHxCItem` function should be used for creating an item of the
        correct type.

        .. todo:: link with cfunc

    """
    #: Class attribute indicating which type of item it handles, this is used
    #:  by :func:`GetHxCItem` for determining if this is the good object to
    #:  instantiate. All abstract class should have a value of -1 for this
    #:  object, non-abstract class should have a value corresponding to the
    #:  :class:`HxCType` they handle.
    TYPE_HANDLE = -1

    def __init__(self, citem):
        """
            Constructor for the abstract class :class:`HxCItem` . This should
            never be used directly.

            :param citem: a ``citem_t`` object, in practice this should always
                be a ``cexpr_t`` or a ``cinsn_t`` object.
        """
        #: The ``citem_t`` object from ida, this is conserved at this level
        #:  for providing a few functionnality compatible between
        #:  :class:`HxCExpr` and :class:`HxCStatement` .
        self._citem = citem

    @property
    def ea(self):
        """
            Property which return the address corresponding to this item.

            .. todo:: check this, not sure if it even works.
        """
        return self._citem.ea

    @property
    def is_expr(self):
        """
            Property which return true if this item is a C Expression
            (:class:`HxCExpr`, ``cexpr_t``).
        """
        return self._citem.is_expr()

    @property
    def is_statement(self):
        """
            Property which return true if this item is a C Statement
            (:class:`HxCStatement`, ``cinsn_t``).
        """
        return not self.is_expr

    @property
    def _ctype(self):
        """
            Property which return the :class:`HxCType` (``ctype_t``) of this
            object.

            :return int: One of the :class:`HxCType` constant value.
        """
        return self._citem.op

    @classmethod
    def is_handling_type(cls, typ):
        """
            Class method which return True if the function handle the type
            passed as argument.

            :param typ: One of the :class:`HxCType` value.
        """
        return cls.TYPE_HANDLE == typ



def GetHxCItem(citem):
    """
        Function which convert a ``citem_t`` object from ida to one of the
        child object of :class:`HxCItem` . This should in particular be used
        for converting ``cexpr_t`` and ``cinsn_t`` in their correct object for
        bip.

        If no :class:`HxCItem` child object exist a ``ValueError`` exception
        will be raised.

        .. todo:: maybe return None instead of raising an exception ?

        :param citem: A ``citem_t`` from ida.
        :return: The equivalent object to the ``citem_t`` for bip. This will
            be an object which inherit from :class:`HxCItem` .
    """
    done = set()
    todo = set(HxCItem.__subclasses__())
    while len(todo) != 0:
        cl = todo.pop()
        if cl in done:
            continue
        if cl.is_handling_type(citem.op):
            return cl(citem)
        else:
            done.add(cl)
            todo |= set(cl.__subclasses__())
    raise ValueError("GetHxCItem function could not find an object matching the citem_t type provided")


