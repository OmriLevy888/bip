import enum
import ida_hexrays


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
    USE_KEYBOARD            = 0x40000000    # ida_hexrays.USE_KEYBOARD
    USE_MOUSE               = 0x80000000    # ida_hexrays.USE_MOUSE


_DOCSTRINGS = {
    HexRaysEvents.lvar_name_changed:
'''
Called whenever the name of a variable is changed in HexRays.

def callback(var: HxLvar, is_user_name: bool) -> None
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
                    self._hook(event, *args, **kwargs)
                else:
                    self._hook(*args, **kwargs)
            except:
                # TODO: print exception
                pass

        def lvar_name_changed(self, vu, v, name, is_user_name):
            if HexRaysEvents.lvar_name_changed & self._mask:
                from bip.hexrays.hx_lvar import HxLvar
                var = HxLvar(v, vu.cfunc)
                self._invoke_hook(HexRaysEvents.lvar_cmt_changed, var, is_user_name)
            return 0

    hook_class = HexRaysHook(hook, mask, pass_event_on_callback)
    hook_class.hook()
    _reigstered_hooks[hook].hooks.append(hook_class)


def _hook_hexrays_events(hook, mask, pass_event_on_callback=True):
    events = sum(event.value for event in mask if isinstance(event, HexRaysEvents))
    _handle_hexrays_hook(hook, events, pass_event_on_callback)


def register_hook(hook, event):
    """
        TODO: write this
    """
    if hook in _reigstered_hooks:
        raise RuntimeError(f'Already hooked (try using set_hook_mask)')

    mask = (event,)
    _reigstered_hooks[hook] = RegisteredHook(mask)
    if isinstance(event, HexRaysEvents):
        _hook_hexrays_events(hook, mask, pass_event_on_callback=False)


def register_hook_mask(hook, mask):
    """
        TODO: write this
    """
    if hook in _reigstered_hooks:
        raise RuntimeError(f'Already hooked (try using set_hook_mask)')

    try:
        _ = (e for e in mask)
    except TypeError:
        mask = (mask,)

    _reigstered_hooks[hook] = RegisteredHook(mask)
    _hook_hexrays_events(hook, mask)


def unregister_hook(hook):
    """
        TODO: write this
    """
    if hook not in _reigstered_hooks:
        raise RuntimeError(f'Attempt to unregister non existant hook')

    _reigstered_hooks[hook].unregister()
    del _reigstered_hooks[hook]


def unregister_all_hooks():
    """
        TODO: write this
    """
    for hook in _reigstered_hooks.values():
        hook.unregister()
    _reigstered_hooks.clear()


def get_hook_mask(hook):
    """
        TODO: write this
    """
    if hook not in _reigstered_hooks:
        raise RuntimeError(f'Attempt to get mask of non existant hook')

    return _reigstered_hooks[hook].mask


def is_hook_register_for(hook, mask):
    """
        TODO: write this
    """
    if hook not in _reigstered_hooks:
        return False

    try:
        return mask == _reigstered_hooks[hook].mask or mask in \
            _reigstered_hooks[hook].mask
    except:
        return False


def set_hook_mask(hook, mask):
    """
        TODO: write this
    """
    unregister_hook(hook)
    register_hook(hook, mask)
