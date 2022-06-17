import idaapi
import idc
import ida_segment
import enum


class SegmentClass(enum.Enum):
    CODE    = "CODE"
    DATA    = "DATA"
    CONST   = "CONST"
    STACK   = "STACK"
    BSS     = "BSS"
    XTRN    = "XTRN"
    COMM    = "COMM"
    ABS     = "ABS"


class BipSegment:
    """
        TODO: write this
    """

    def __init__(self, start_ea):
        self._segment = idaapi.getseg(start_ea)

    @property
    def name(self):
        """
            TODO: write this
        """
        return idc.get_segm_name(self.start_ea)

    @name.setter
    def name(self, value):
        """
            TODO: write this
        """
        ida_segment.set_segm_name(self._segment, value)

    @property
    def start_ea(self):
        """
            TODO: write this
        """
        return self._segment.start_ea

    @start_ea.setter
    def start_ea(self, value):
        """
            TODO: write this
        """
        ida_segment.set_segm_start(self.start_ea, value, 0)

    @property
    def end_ea(self):
        """
            TODO: write this
        """
        return self._segment.end_ea

    @end_ea.setter
    def end_ea(self, value):
        """
            TODO: write this
        """
        ida_segment.set_segm_end(self.start_ea, value, 0)

    @property
    def permissions(self):
        """
            TODO: write this
        """
        formatted_perms = 0
        if self._segment.perm & ida_segment.SEGPERM_READ:
            formatted_perms |= 4
        if self._segment.perm & ida_segment.SEGPERM_WRITE:
            formatted_perms |= 2
        if self._segment.perm & ida_segment.SEGPERM_EXEC:
            formatted_perms |= 1
        return formatted_perms

    @permissions.setter
    def permissions(self, value):
        """
            TODO: write this
        """
        formatted_perms = 0
        if value & 4:
            formatted_perms |= ida_segment.SEGPERM_READ
        if value & 2:
            formatted_perms |= ida_segment.SEGPERM_WRITE
        if value & 1:
            formatted_perms |= ida_segment.SEGPERM_EXEC
        self._segment.perm = formatted_perms
