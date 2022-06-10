import enum
import ida_hexrays

from bip.hexrays.hx_cfunc import HxCFunc


class HxUIFlags(enum.IntEnum):
    REUSE           = 0x00
    NEW_WINDOW      = 0x01
    REUSE_ACTIVE    = 0x02
    NO_WAIT         = 0x08


_FLAGS_DOCSTRIGNS = {
    HxUIFlags.REUSE:
"""
Reuse existing window
""",
    HxUIFlags.NEW_WINDOW:
"""
Open new window
""",
    HxUIFlags.REUSE_ACTIVE:
"""
Reuse existing window, only if the currently active widget is a pseudocode view
""",
    HxUIFlags.NO_WAIT:
"""
Do not display waitbox if decompilation happens
""",
}
for flag in HxUIFlags:
    setattr(flag, '__doc__', _FLAGS_DOCSTRIGNS[flag])


class HxUI:
    """
        Object representing a decompilation window.
    """

    def __init__(self, ea=None, vdui=None, flags=HxUIFlags.NO_WAIT):
        """
            Create a new HxUI object.

            :param int ea: The address to open the HxUI object at.
            :param vdui_t vdui: The IDA ui object.
            :param :class:`HxUIFlags` flags: How to open the pseudocode window.
                Default is HxUIFlags.NO_WAIT.
        """
        if ea is None and vdui is None:
            raise ValueError(f'Both ea and vdui are None')
        elif ea is not None and vdui is not None:
            raise ValueError(f'Can only pass either ea or vdui')
        elif ea is not None:
            self._vdui = ida_hexrays.open_pseudocode(ea, flags)
        else:
            self._vdui = vdui

    @property
    def vdui(self):
        """
            Property which return the underlying vdui_t object.

            :return :class:`ida_hexrays.vdui_t`: The underlying vdui_t object
        """
        return self._vdui

    ############################### PROPERTIES ###############################

    @property
    def visible(self):
        """
            Property which return whether the view is visible.

            :return bool: Whether the view is visibile.
        """
        return self.vdui.visible()

    @visible.setter
    def visible(self, value):
        """
            Setter for changing whether the view is visible.

            :param bool value: True to make the view visible, False to hide it.
        """
        self.vdui.set_visible(value)

    @property
    def valid(self):
        """
            Property which return whether the function in the view is valid or
            needs refreshing.

            :return bool: Whether the function is valid.
        """
        return self.vdui.valid()

    @valid.setter
    def valid(self, value):
        """
            Setter for marking the function as valid or invalid.

            :param bool value: True to mark the function as valid, False to
                mark it as invalid.
        """
        self.vdui.set_valid(value)

    @property
    def locked(self):
        """
            Property which return whether the function is locked.

            :return bool: Whether the function is locked.
        """
        return self.vdui.locked()

    @locked.setter
    def locked(self, value):
        """
            Setter for locking the function.

            :param str value: True to lock the function, False to release it.
        """
        self.vdui.set_locked(value)

    @property
    def func(self):
        """
            Proeprty which return the function in the view.

            :return: :class:`HxCFunc` representing the function in the view.
        """
        return HxCFunc(self.vdui.cfunc)

    @func.setter
    def func(self, value):
        """
            Setter to change the function in the view.

            :param :class:`HxCFunc` value: The function to change to.
        """
        self.vdui.switch_to(value.cfunc)

    ################################# UI OPS #################################

    def refresh_view(self, redo_mba=True):
        """
            Refresh HexRays window.

            :param bool redo_mba: Determine whether to redecompile the current
                function. Default is to redecompile.
        """
        self.vdui.refresh_view(redo_mba)

    def clear(self):
        """
            Clear the pseudocode window.
        """
        self.vdui.clear()

    ################################# CTREE ##################################

    @property
    def item_under_mouse(self):
        """
            TODO: write this
            TODO: make this return HxCnode object
        """
        if not self.vdui.get_current_item(ida_hexrays.USE_MOUSE):
            return None

        return self.vdui.item
