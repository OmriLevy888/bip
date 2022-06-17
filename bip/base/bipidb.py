
# define BipIdb and some helper functions for easier scripting (at the end).

import ida_kernwin
import idaapi
import idc
import idautils
import ida_segment
import functools
import collections

from bip.base.bipsegment import BipSegment, SegmentClass


class BipIdb(object):
    """
        Class for representing the idb loaded by IDA, this has the goal to
        provide access to things specific to the IDB.

        Currently this contain only static methods.
    """

    @staticmethod
    def ptr_size():
        """
            Return the number of bits in a pointer.

            :rtype: int
        """
        info = idaapi.get_inf_structure()

        if info.is_64bit():
            bits = 64
        elif info.is_32bit():
            bits = 32
        else:
            bits = 16

        return bits

    @staticmethod
    def min_ea():
        """
            Return the lowest mapped address of the IDB.
        """
        return idc.get_inf_attr(idc.INF_MIN_EA)

    @staticmethod
    def max_ea():
        """
            Return the highest mapped address of the IDB.
        """
        return idc.get_inf_attr(idc.INF_MAX_EA)

    @staticmethod
    def image_base():
        """
            Return the base address of the image loaded in the IDB.

            This is different from :meth:`~BipIdb.min_ea` which is the lowest
            *mapped* address.
        """
        return idaapi.get_imagebase()

    @staticmethod
    def current_addr():
        """
            Return current screen address.

            :return: The current address selected.
        """
        return ida_kernwin.get_screen_ea()

    @staticmethod
    def relea(addr):
        """
            Calculate the relative address compare to the IDA image base.
            The calcul done is ``ADDR - IMGBASE``.

            The opposite of this function is :func:`absea`.

            :param int addr: The absolute address to translate.
            :return: The offset from image base corresponding to ``addr``.
            :rtype: int
        """
        return addr - idaapi.get_imagebase()

    @staticmethod
    def absea(offset):
        """
            Calculate the absolute address from an offset of the image base.
            The calcul done is ``OFFSET + IMGBASE`` .

            The opposite of this function is :func:`relea`.

            :param int offset: The offset from the beginning of the image base
                to translate.
            :return: The absolute address corresponding to the offset.
            :rtype: int
        """
        return offset+idaapi.get_imagebase()

    @staticmethod
    def strings():
        """
            Get all the strings in the binary identified by IDA.

            :return: All strings in IDB.
            :rtype: Iterable :class:`BipData`
        """
        from .bipelt import GetElt
        for s in idautils.Strings():
            yield GetElt(s.ea)

    @staticmethod
    def imports():
        """
            Get all imported symbols.

            :return: Iterable of named tuples with fields for ``module_name``,
                ``name``, ``ea`` and ``ordinal``
        """
        imported_symbol = collections.namedtuple('imported_symbol',
                                                 ('module_name',
                                                  'name',
                                                  'ea',
                                                  'ordinal'))

        def callback(container, ea, name, ordinal):
            container.append((ea, name, ordinal))
            return True

        nimps = idaapi.get_import_module_qty()
        for module_idx in range(nimps):
            module_name = idaapi.get_import_module_name(module_idx)
            container = list()
            bound_callback = functools.partial(callback, container)
            idaapi.enum_import_names(module_idx, bound_callback)
            for ea, name, ordinal in container:
                yield imported_symbol(module_name, name, ea, ordinal)


    @staticmethod
    def exports():
        """
            Get all exported symbols (entry ordinal is the same as ea).

            :return: Iterable of either tuples where the first item is
                the ordinal and the second is either :class:`BipData` or
                :class:`BipFunction`.
        """
        from .bipelt import GetElt
        for export in idautils.Entries():
            idx, ordinal, ea, name = export
            elt = GetElt(ea)
            if elt.is_code:
                elt = elt.func
            yield ordinal, elt

    @staticmethod
    def segments():
        """
            TODO: write this.
        """
        return [BipSegment(ea) for ea in idautils.Segments()]

    @staticmethod
    def get_segment(ea=None, name=None):
        """
            TODO: write this
        """
        if ea is None and name is None:
            raise ValueError(f"Must pass either name or ea")
        elif ea is not None and name is not None:
            raise ValueError(f"Can only pass either name or ea")
        elif ea is not None:
            return BipSegment(ea)
        else:
            return BipSegment(ida_segment.get_segm_by_name(name).start_ea)

    @staticmethod
    def add_segment(start_ea, end_ea, name, segment_class="DATA", permissions=4):
        """
            TODO: write this
        """
        if isinstance(segment_class, SegmentClass):
            segment_class = segment_class.value
        ida_segment.add_segm(0, start_ea, end_ea, name, segment_class)
        seg = BipIdb.get_segment(start_ea)
        seg.permissions = permissions

    @staticmethod
    def segment_from_data(start_ea, name, data, segment_class="DATA", permissions=4):
        """
            TODO: write this
        """
        BipIdb.add_segment(start_ea, start_ea + len(data), name, segment_class, permissions)
        from bip import BipData
        BipData.set_bytes(start_ea, data)


def min_ea():
    """
        Return the lowest mapped address of the IDB.
        Wrapper on :meth:`BipIdb.min_ea`.
    """
    return BipIdb.min_ea()

def max_ea():
    """
        Return the highest mapped address of the IDB.
        Wrapper on :meth:`BipIdb.max_ea`.
    """
    return BipIdb.max_ea()

def Here():
    """
        Return current screen address.

        :return: The current address.
    """
    return BipIdb.current_addr()
