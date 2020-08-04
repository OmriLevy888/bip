import importlib
import inspect
import os

import idaapi

from .plugin import BipPlugin
from .menutb import add_top_menu

#: Global object :class:`BipPluginManager` which should be use by everybody
#:  access is made through :func:`get_plugin_manager`.
BPM = None

class BipPluginManager(idaapi.plugin_t):
    """
        Class for the plugin manager of Bip. This class represent the object
        in charge of loading all of the :class:`BipPlugin`. For accessing the
        plugin manager use :func:`get_plugin_manager`.

        This class also create the ``Bip`` directory as a top level menu
        entry. It is expected that plugins should add their menu actions in
        this directory (using the :func:`menu` decorator).
        
        This object should not be instantiated by the user but should already
        be created when IDA load the plugin. This is a *real* IDAPython plugin
        as understood by IDA.

        .. todo:: this should handle load order and plugin dependency
    """
    flags = 0
    comment = "Bip plugin manager, managed bip plugins"
    wanted_name = "Bip Plugin Manager"
    help = "The BipPluginManager is in charge of loading, unloading and in a general way manage BipPlugin objects. See bip documentation for more information."
    wanted_hotkey = "Ctrl-0"

    #: List of module names from which to load the :class:`BipPlugin`, 
    #: by default this contains, only the ``bipplugin`` module, but other
    #: can be added by users.
    _modbipplug = ["bipplugin"]

    def __init__(self):
        """
            Constructor for the :class:`BipPluginManager`, use
            :func:`get_plugin_manager` for getting this object.
        """
        #: dict of :class:`BipPlugin`, keys are name of the plugin class, and
        #:  value are the class.
        self._plugins = {}
        #: list of loaded :class:`BipPlugin`, keys are name of the plugin
        #:  class, and value are the object.
        self._loaded = {}
        #: indicate if main loading is already done, used
        #:  by :meth:`addld_plugin` .
        self._is_loaded = False
        super(BipPluginManager, self).__init__()

    def init(self):
        """
            Init method called by IDA. This will instantiate and load all
            plugins already registered at this point. This is also the
            function in charge of creating the top level menu ``Bip``.
        """
        add_top_menu("Bip", before="Help")
        for name in self._modbipplug:
            self.find_load_plugins(name)
        self.load_all()
        self._is_loaded = True
        return idaapi.PLUGIN_KEEP

    @property
    def is_ready(self):
        """
            Property indicating the :class:`BipPluginManager` is ready and has
            loaded the plugin.
        """
        return self._is_loaded

    def find_load_plugins(self, name):
        """
            Use the :meth:`BipPluginLoader.get_plg_from_files_in_module` for
            locating all :class:`BipPlugin` in a module and load them.
            
            .. note::

                This functions allows to load all plugins define in a
                particular folder. This folder should be itself a module.
                This is how the plugins from the ``bipplugin`` folder are
                loaded.

            :param str name: Name of the module in which all plugins are
                define.
        """
        d = BipPluginLoader.get_plg_from_files_in_module(name)
        for k in d:
            self.addld_plugin(k, d[k])#, ifneeded=True)

    def load_all(self):
        """
            Load all plugins which have not already been loaded up to this
            point.
            
            This method is called automatically when the
            :meth:`~BipPluginManager.init` function is called by IDA.

            .. todo:: handle exception generated by the plugins
        """
        for k, v in self._plugins.items():
            if k in self._loaded: # this plugin as already been loaded
                continue
            if not v.to_load(): # this plugin do not want to be loaded
                continue
            p = v() # create the plugin
            self._loaded[k] = p # add it to the list
            p.load() # call the load method

    def load_one(self, name, forced=False, ifneeded=False):
        """
            Load a plugin from its name.

            A plugin should already have been added, see :meth:`add_plugin` .
            For adding and trying to load a plugin at the same time use
            :meth:`addld_plugin` .

            For a plugin this means: it will be check if the
            :meth:`~BipPlugin.to_load` return True and if it so an object
            will be created, and the :meth:`~BipPlugin.load` method will be
            called.

            :param name: The name of the plugin to load.
            :param forced: If True (default False) the call to
                :meth:`~BipPlugin.to_load` will be skipped.
            :param ifneeded: If True will load the plugin
                only if not already loaded, by default (False) will raise an
                exception.
            :raise RuntimeError: If the plugin was not found or already
                loaded.
            :return: the :class:`BipPlugin` object created on succes, None
                if the plugin did not wanted to be loaded.
        """
        if name in self._loaded:
            if ifneeded:
                return self._loaded[name]
            else:
                raise RuntimeError("Plugin {} is already loaded".format(name))
        if name not in self._plugins:
            raise RuntimeError("Unable to locate plugin {}".format(name))
        cl = self._plugins[name]
        if not forced and not cl.to_load():
            return
        p = cl() # create the plugin
        self._loaded[name] = p # add it to the list
        p.load() # call the load method

    def add_plugin(self, name, cls, ifneeded=False):
        """
            Add a plugin to the plugin manager. This will not load the plugin
            directly. It will be loaded when a call to :meth:`load_all` is
            made or, if not already done, when the :class:`BipPluginManager`
            will be loaded by IDA.

            For adding and trying to load a plugin at the same time use
            :meth:`addld_plugin` .

            :param name: Name of the plugin, this should match the name of the
                class.
            :param cls: Class of the plugin to add, the plugin manager will
                instantiate it.
            :param ifneeded: If True (default False) will not raise an
                exception if a plugin of the same name is already added.
            :raise RuntimeError: If the plugin is already registered.
        """
        if name in self._plugins:
            if ifneeded:
                if name not in self._loaded:
                    # this is for the particular case where a plugin class is
                    #   defined again before being loaded by the plugin
                    #   manager. This will trigger a problem because of an
                    #   incoherance between the class stored in the plugin
                    #   manager and in the module. The underlying problem
                    #   come from the fact that IDA load the plugins several
                    #   time
                    self._plugins[name] = cls
                return
            else:
                raise RuntimeError("Plugin {} is already registered!".format(name))
        self._plugins[name] = cls

    def addld_plugin(self, name, cls, forced=False, ifneeded=False):
        """
            Add a plugin and try to load it. If the :class`BipPluginManager`
            has not already been loaded the plugin will try to be loaded at
            that time (see :meth:`load_one` for details on what loading means
            for a plugin).

            :param name: Name of the plugin, this should match the name of the
                class.
            :param cls: Class of the plugin to add, the plugin manager will
                instantiate it itself.
            :param forced: If True (default False) it will not check if the
                :class:BipPluginManager` as been loaded by IDA, nor will it
                call the :meth:`~BipPlugin.to_load` of the plugin.
            :param ifneeded: If True (default False) will add and load the
                plugin only if not already present internally.
            :raise RuntimeError: If the plugin is already registered or
                already loaded and ``ifneeded`` is False.
        """
        self.add_plugin(name, cls, ifneeded=ifneeded)
        if not forced and not self._is_loaded:
            return
        self.load_one(name, forced=forced, ifneeded=ifneeded)

    def get_plugin(self, name):
        """
            Get a plugin instance from its name. The plugin must be loaded
            for this method to work.
            
            :param name: A string representing the :class:`BipPlugin` name
                or a subclass of :class:`BipPlugin`.
            :return: An object (instance) which inherit from
                :class:`BipPlugin` or ``None`` if not found.
        """
        if isinstance(name, type): # a class was given in parameter
            name = name.__name__
        if name in self._loaded:
            return self._loaded[name]
        return None

    def __getitem__(self, key):
        """
            Get a plugin instance from its name or class. This is a wrapper
            on :meth:`get_plugin` but it will raise a ``KeyError`` in case
            the plugin was not found.
        """
        p = self.get_plugin(key)
        if p is None:
            raise KeyError("Plugin {} instance was not found".format(key))
        return p

    def __contains__(self, key):
        """
            Check if a plugin was loaded by the :class:`BipPluginManager` and
            can be access through it.
        """
        if isinstance(key, type):
            key = key.__name__
        return key in self._loaded

    def run(self, arg):
        # TODO: this should allow to see and manage plugins
        #   IDA action, mapped on Ctrl-0
        pass
    
    def term(self):
        pass

class BipPluginLoader(object):
    """
        Class for utility functions for loading plugins from modules and
        files.
    """

    @staticmethod
    def get_plugins_from_module(mod, thismodonly=True):
        """
            Return a dict of the different classes which inherit from
            :class:`BipPlugin` in a module. Key of the dictionnary are the
            name in the module and values are the :class:`BipPlugin` classes.

            :param mod: The module in which to search for :class:`BipPlugin`.
            :param bool thismodonly: A boolean (default True) indicating if
                only the plugin from the current module should be used. This
                is for avoiding to get plugins imported from another modules.
            :return: A dict of the name associated with the :class:`BipPlugin`
                classes.
        """
        d = {}
        for name in mod.__dict__:
            # check if we have a class which is a BipPlugin or the BipPlugin
            #   class itself
            obj = mod.__dict__[name]
            if ((not inspect.isclass(obj)) or (not issubclass(obj, BipPlugin))
                    or (obj == BipPlugin)):
                continue
            # check if it is in the correct module
            if thismodonly and obj.__module__ != mod.__name__:
                continue
            d[name] = obj
        return d

    @staticmethod
    def get_plg_from_files_in_module(name, thismodonly=True):
        """
            From the name of a module, will look for the file present in the
            module directory and import all the ``.py`` files present in it
            (at the first level), it will then search all the
            :class:`BipPlugin` present in those files and return a dict of the
            plugins (see :meth:`~BipPluginLoader.get_plugins_from_module`).

            This method is used for loading the plugins located in the
            ``bipplugin`` folder.

            .. warning:: If two plugins have the same name only one will be loaded.

            :param str name: Name of the module in which to search for ``.py``
                containing :class:`BipPlugin`. It should be possible to
                import both the module (``import NAME``) and the sub-files
                (``import NAME.SUBFILE``).
            :param bool thismodonly: Indicate if plugins not instanciated in
                the module should be imported,
                see :meth:`~BipPluginLoader.get_plugins_from_module`.
            :return: A dict of the name associated with the :class:`BipPlugin`
                classes, see :meth:`~BipPluginLoader.get_plugins_from_module`.
        """
        mod = importlib.import_module(name)
        paths = mod.__path__
        for path in paths:
            d = {}
            for f in os.listdir(path):
                if f[-3:] != ".py" or (not os.path.isfile(os.path.join(path, f))) or f == "__init__.py":
                    continue
                m = importlib.import_module(name + "." + f[:-3])
                d.update(BipPluginLoader.get_plugins_from_module(m, thismodonly=thismodonly))
        return d

def get_plugin_manager():
    """
        Function allowing access to the :class:`BipPluginManager` singleton.
    """
    global BPM
    if BPM is None:
        BPM = BipPluginManager()
    return BPM




