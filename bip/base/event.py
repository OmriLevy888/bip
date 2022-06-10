import enum
import ida_hexrays

from bip.hexrays.hx_ui import HxUI
from bip.gui.keyboard import KeyPress


class HexRaysEvents(enum.IntEnum):
    """
        Enum object for the hexrays event. This is documented in
        https://www.hex-rays.com/products/decompiler/manual/sdk/hexrays_8hpp.shtml
        https://www.hex-rays.com/products/decompiler/manual/sdk/hexrays_8hpp_source.shtml
        and defined in ``ida_hexrays`` python file.

        .. todo:: make wrapper on functions and stuff

    """
    flowchart               = 0x00000001    # ida_hexrays.hxe_flowchart
    stkpnts                 = 0x00000002    # ida_hexrays.hxe_stkpnts
    prolog                  = 0x00000004    # ida_hexrays.hxe_prolog
    microcode               = 0x00000008    # ida_hexrays.hxe_microcode
    preoptimized            = 0x00000010    # ida_hexrays.hxe_preoptimized
    locopt                  = 0x00000020    # ida_hexrays.hxe_locopt
    prealloc                = 0x00000040    # ida_hexrays.hxe_prealloc
    glbopt                  = 0x00000080    # ida_hexrays.hxe_glbopt
    structural              = 0x00000100    # ida_hexrays.hxe_structural
    maturity                = 0x00000200    # ida_hexrays.hxe_maturity
    interr                  = 0x00000400    # ida_hexrays.hxe_interr
    combine                 = 0x00000800    # ida_hexrays.hxe_combine
    print_func              = 0x00001000    # ida_hexrays.hxe_print_func
    func_printed            = 0x00002000    # ida_hexrays.hxe_func_printed
    resolve_stkaddrs        = 0x00004000    # ida_hexrays.hxe_resolve_stkaddrs
    open_pseudocode         = 0x00008000    # ida_hexrays.hxe_open_pseudocode
    switch_pseudocode       = 0x00010000    # ida_hexrays.hxe_switch_pseudocode
    refresh_pseudocode      = 0x00020000    # ida_hexrays.hxe_refresh_pseudocode
    close_pseudocode        = 0x00040000    # ida_hexrays.hxe_close_pseudocode
    keyboard                = 0x00080000    # ida_hexrays.hxe_keyboard
    right_click             = 0x00100000    # ida_hexrays.hxe_right_click
    double_click            = 0x00200000    # ida_hexrays.hxe_double_click
    curpos                  = 0x00400000    # ida_hexrays.hxe_curpos
    create_hint             = 0x00800000    # ida_hexrays.hxe_create_hint
    text_ready              = 0x01000000    # ida_hexrays.hxe_text_ready
    populating_popup        = 0x02000000    # ida_hexrays.hxe_populating_popup
    lvar_name_changed       = 0x04000000    # ida_hexrays.lxe_lvar_name_changed
    lvar_type_changed       = 0x08000000    # ida_hexrays.lxe_lvar_type_changed
    lvar_cmt_changed        = 0x10000000    # ida_hexrays.lxe_lvar_cmt_changed
    lvar_mapping_changed    = 0x20000000    # ida_hexrays.lxe_lvar_mapping_changed
    cmt_change              = 0x40000000    # ida_hexrays.hxe_cmt_changed


_DOCSTRINGS = {
    HexRaysEvents.open_pseudocode:
'''
Called whenever opening a new HexRays view.

def callback(ui: HxUI) -> None
''',
    HexRaysEvents.switch_pseudocode:
'''
Called whenever switching the function in an open HexRays view.

def callback(ui: HxUI) -> None

NOTE: The text has not been refreshsed yet at this point, only cfunc and mba
      pointers are ready.
''',
    HexRaysEvents.refresh_pseudocode:
'''
Called whenever refreshing an open HexRays view.

def callback(ui: HxUI) -> None

NOTE: Adding/removing pseudocode lines is forbidden in this event (see also:
      HexRaysEvents.text_ready which happens earlier).
''',
    HexRaysEvents.close_pseudocode:
'''
Called whenever closing a HexRays view.

def callback(ui: HxUI) -> None
''',
    HexRaysEvents.keyboard:
'''
Called whenever a key has bin hit.

def callback(ui: HxUI, key_press: KeyPress) -> bool

Return True if handled the keypress, False otherwise.
''',
    HexRaysEvents.right_click:
'''
Called whenever a right click has occured.

def callback(ui: HxUI) -> None

NOTE: Use HexRaysEvents.populating_popup to in case you want to add items in a
      popup menu.
''',
    HexRaysEvents.double_click:
'''
Called whenever a double clicked has occured.

def callback(ui: HxUI, shift_state: bool) -> bool

Return True if handled the double click, False otherwise.
''',
    HexRaysEvents.curpos:
'''
Called whenever the cursor position has changed.

def callback(ui: HxUI) -> None
''',
    HexRaysEvents.create_hint:
'''
Called whenever creating a hint.

def callback(ui: HxUI) -> HxHint

0 -> continue collecting hints with other subscribers
1 -> stop collecting hints
1, '...', 1 -> replace original hint with '...'
2, '...', 1 -> prefix original hint with '...'
''',
    HexRaysEvents.text_ready:
'''
Called whenever the decompiled text is ready.

def callback(ui: HxUI) -> None

NOTE: Obsolete. Please use HexRAysEvents.func_printed instead.
''',
    HexRaysEvents.populating_popup:
'''
Caleled whenever populating a popup menu (can be used to add menu items).

def callback(widget: TWidget, popup_handle: TPopupMenu, ui: HxUI) -> None
''',
    HexRaysEvents.lvar_name_changed:
'''
Called whenever the name of a variable is changed in HexRays.

def callback(ui: HxUI, var: HxLvar) -> None
''',
    HexRaysEvents.lvar_type_changed:
'''
Called whenever the type of a variable is changed in HexRays.

def callback(ui: HxUI, var: HxLvar) -> None
''',
    HexRaysEvents.lvar_cmt_changed:
'''
Called whenever the comment of a variable is changed in HexRays.

def callback(ui: HxUI, var: HxLvar) -> None
''',
}
for event in HexRaysEvents:
    if event in _DOCSTRINGS:
        setattr(event, '__doc__', _DOCSTRINGS[event])


class RegisteredHook:
    def __init__(self, mask):
        self.hooks = list()
        self.mask = mask

    def unregister(self):
        for hook in self.hooks:
            hook.unhook()

_reigstered_hooks = dict()


def _handle_hexrays_hook(hook, mask, pass_event_on_callback):
    class HexRaysHook(ida_hexrays.Hexrays_Hooks):
        def __init__(self, hook, mask, pass_event_on_callback, *args, **kwargs):
            self._hook = hook
            self._mask = mask
            self._pass_event_on_callback = pass_event_on_callback
            super(HexRaysHook, self).__init__(*args, **kwargs)

        def _invoke_hook(self, event, *args, **kwargs):
            try:
                if self._pass_event_on_callback:
                    return self._hook(event, *args, **kwargs)
                else:
                    return self._hook(*args, **kwargs)
            except:
                import traceback
                print(traceback.format_exc())

        def open_pseudocode(self, vu):
            if HexRaysEvents.open_pseudocode & self._mask:
                self._invoke_hook(HexRaysEvents.open_pseudocode, HxUI(vdui=vu))
            return 0

        def switch_pseudocode(self, vu):
            if HexRaysEvents.switch_pseudocode & self._mask:
                self._invoke_hook(HexRaysEvents.switch_pseudocode, HxUI(vdui=vu))
            return 0

        def refresh_pseudocode(self, vu):
            if HexRaysEvents.refresh_pseudocode & self._mask:
                self._invoke_hook(HexRaysEvents.refresh_pseudocode, HxUI(vdui=vu))
            return 0

        def close_pseudocode(self, vu):
            if HexRaysEvents.close_pseudocode & self._mask:
                self._invoke_hook(HexRaysEvents.close_pseudocode, HxUI(vdui=vu))
            return 0

        def keyboard(self, vu, key_code, shift_state):
            if HexRaysEvents.keyboard & self._mask:
                shift_state = bool(shift_state & 0x2000000)
                return 1 if self._invoke_hook(HexRaysEvents.keyboard,
                                              HxUI(vdui=vu), KeyPress(key_code, shift_state)) else 0
            return 0

        def right_click(self, vu):
            if HexRaysEvents.right_click & self._mask:
                self._invoke_hook(HexRaysEvents.right_click, HxUI(vdui=vu))
            return 0

        def double_click(self, vu, shift_state):
            if HexRaysEvents.double_click & self._mask:
                shift_state = bool(shift_state & 1)
                return 1 if self._invoke_hook(HexRaysEvents.double_click,
                                              HxUI(vdui=vu), shift_state) else 0
            return 0

        def curpos(self, vu):
            if HexRaysEvents.curpos & self._mask:
                self._invoke_hook(HexRaysEvents.curpos, HxUI(vdui=vu))
            return 0

        def create_hint(self, vu):
            if HexRaysEvents.create_hint & self._mask:
                return self._invoke_hook(HexRaysEvents.create_hint, HxUI(vdui=vu))
            return 0

        def text_ready(self, vu):
            if HexRaysEvents.text_ready & self._mask:
                self._invoke_hook(HexRaysEvents.text_ready, HxUI(vdui=vu))
            return 0

        def populating_popup(self, widget, popup_handle, vu):
            if HexRaysEvents.populating_popup & self._mask:
                self._invoke_hook(HexRaysEvents.populating_popup,
                                  widget, popup_handle, HxUI(vdui=vu))
            return 0

        def lvar_name_changed(self, vu, v, name, is_user_name):
            if HexRaysEvents.lvar_name_changed & self._mask:
                from bip.hexrays.hx_lvar import HxLvar
                var = HxLvar(v, vu.cfunc)
                self._invoke_hook(HexRaysEvents.lvar_name_changed, HxUI(vdui=vu), var)
            return 0

        def lvar_type_changed(self, vu, v, tinfo):
            if HexRaysEvents.lvar_type_changed & self._mask:
                from bip.hexrays.hx_lvar import HxLvar
                var = HxLvar(v, vu.cfunc)
                self._invoke_hook(HexRaysEvents.lvar_type_changed, HxUI(vdui=vu), var)
            return 0

        def lvar_cmt_changed(self, vu, v, cmt):
            if HexRaysEvents.lvar_cmt_changed & self._mask:
                from bip.hexrays.hx_lvar import HxLvar
                var = HxLvar(v, vu.cfunc)
                self._invoke_hook(HexRaysEvents.lvar_cmt_changed, HxUI(vdui=vu), var)
            return 0

    hook_class = HexRaysHook(hook, mask, pass_event_on_callback)
    hook_class.hook()
    _reigstered_hooks[hook].hooks.append(hook_class)


def _hook_hexrays_events(hook, mask, pass_event_on_callback=True):
    events = sum(event.value for event in mask if isinstance(event, HexRaysEvents))
    _handle_hexrays_hook(hook, events, pass_event_on_callback)


def register_hook(hook, event):
    """
        Register a hook to a single event. See :class:`HexRaysEvents` for all
        possible events.

        :param hook: A function matching the sigrature for the requested event.
        :param event: An event to register to, as defined by the :class:`HexRaysEvents`
            enum.
    """
    if hook in _reigstered_hooks:
        raise RuntimeError(f'Already hooked (try using set_hook_mask)')

    mask = (event,)
    _reigstered_hooks[hook] = RegisteredHook(mask)
    if isinstance(event, HexRaysEvents):
        _hook_hexrays_events(hook, mask, pass_event_on_callback=False)


def register_hook_mask(hook, mask):
    """
        Register a hook to a multiple events. See :class:`HexRaysEvents` for all
        possible events.

        :param hook: A callback, whose first parameter is the event triggered
            and the rest are depending on the triggered event.
        :param mask: An iterable of events to register to, as defined by the
            :class:`HexRaysEvents` enum.
    """
    if hook in _reigstered_hooks:
        raise RuntimeError(f'Already hooked (try using set_hook_mask)')

    try:
        _ = (e for e in mask)
    except TypeError:
        mask = (mask,)

    _reigstered_hooks[hook] = RegisteredHook(mask)
    _hook_hexrays_events(hook, mask)


def register_hook_all(hook):
    """
        Reigster a hook to all events. See :class:`HexRaysEvents` for all
        possible events.

        :param hook: A callback, whose first parameter is the event triggered
            and the rest are depending on the triggered event.
    """
    register_hook_mask(hook, [event for event in HexRaysEvents])


def unregister_hook(hook):
    """
        Unregisters a previously registered hook.

        :param hook: The hook to unregister.
    """
    if hook not in _reigstered_hooks:
        raise RuntimeError(f'Attempt to unregister non existant hook')

    _reigstered_hooks[hook].unregister()
    del _reigstered_hooks[hook]


def unregister_all_hooks():
    """
        Unregisters all previously registered hooks.
    """
    for hook in _reigstered_hooks.values():
        hook.unregister()
    _reigstered_hooks.clear()


def get_hook_mask(hook):
    """
        Check what events are caught by a hook.

        :return: An iterable of :class:`HexRayEvents` events.
    """
    if hook not in _reigstered_hooks:
        raise RuntimeError(f'Attempt to get mask of non existant hook')

    return _reigstered_hooks[hook].mask


def set_hook_mask(hook, mask):
    """
        Change mask of previously registered hook. This simply unregisters the
        hook and then reregisters it with the new mask.

        :param hook: The hook to change the mask of.
        :param mask: An iterable of :class:`HexRayEvents` to change the mask to.
    """
    unregister_hook(hook)
    register_hook(hook, mask)
