import ida_hexrays


class HxLine:
    """
        TODO: write this
    """

    def __init__(self, ea, cfunc=None):
        """
            TODO: write this
        """
        if not isinstance(ea, int):
            if hasattr(ea, 'ea') and isinstance(ea.ea, int):
                ea = ea.ea
            else:
                raise ValueError(f"Must passed integer value for ea or something with ea field which is an integer")

        self.ea = ea
        self._cfunc = cfunc
        self._cstr = None

    @property
    def cfunc(self):
        """
            TODO: write this
        """
        if self._cfunc is not None:
            return self._cfunc
        self._cfunc = ida_hexrays.decompile(self.ea)
        return self._cfunc

    @property
    def lineno(self):
        """
            TODO: wrhite this
        """
        from bip.hexrays.hx_cfunc import HxCFunc
        lines = [line.strip() for line in HxCFunc(self.cfunc).cstr.split('\n')]
        return lines.index(self.cstr.strip()) + 1

    @property
    def cstr(self):
        """
            Property which returns the string representation of the line.

            :return: :class:`str` representing this line.
        """
        if self._cstr is not None:
            return self._cstr

        cfunc = self.cfunc
        if self.ea not in cfunc.eamap:
            raise ValueError(f"{hex(self.ea)} not in self.cfunc.eamaps")

        try:
            insnvec = cfunc.eamap[self.ea]
            lines = list()
            for stmt in insnvec:
                qp = ida_hexrays.qstring_printer_t(cfunc.__deref__(), False)
                stmt._print(0, qp)
                s = qp.s.split('\n')[0]
                lines.append(s)
            self._cstr = '\n'.join(lines)
        except ValueError as _:
            # Occurs when printing the last line in a function
            # (invalid INS_EPILOG in method 'cinsn_t__print', argument 1 of type 'cinsn_t const *')
            self._cstr = '}'

        return self._cstr
