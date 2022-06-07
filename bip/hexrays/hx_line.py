import ida_hexrays


class HxLine:
    def __init__(self, ea):
        if not isinstance(ea, int):
            if hasattr(ea, 'ea') and isinstance(ea.ea, int):
                ea = ea.ea
            else:
                raise ValueError(f"Must passed integer value for ea or something with ea field which is an integer")

        self.ea = ea
        self._cfunc = None
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

        insnvec = cfunc.eamap[self.ea]
        lines = list()
        for stmt in insnvec:
            qp = ida_hexrays.qstring_printer_t(cfunc, False)
            stmt._print(0, qp)
            s = qp.s.split('\n')[0]
            lines.append(s)
        self._cstr = '\n'.join(lines)
        return self._cstr
