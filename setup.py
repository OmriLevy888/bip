from setuptools import setup, find_packages
from setuptools.command.install import install
from pathlib import Path
import sys
import os
import shutil
from distutils.dir_util import copy_tree


class InstallBipPluginManager(install):
    def _get_ida_folder(self):
        if sys.platform in ("linux", "linux2", "darwin"):
            return Path(os.getenv('HOME')) / '.idapro'
        elif sys.platform == "win32":
            return Path(os.getenv('APPDATA')) / 'Hex-Rays' / 'IDA Pro'
        
        raise RuntimeError('Unknwown OS do not know where to install')

    def run(self):
        install.run(self)

        print("[+] Setting up bip's plugin manager")
        plugins_folder = self._get_ida_folder() / 'plugins'
        bip_plugins_folder = plugins_folder / 'bipplugin'

        if not bip_plugins_folder.exists():
            bip_plugins_folder.mkdir(parents=True)
            print(f'[+] Created {bip_plugin_loader}')

        plugins_init = bip_plugins_folder / '__init__.py'
        if not plugins_init.exists():
            with open(plugins_init, 'w'): pass
            print(f'[+] Created empty {plugins_init}')

        bip_plugin_loader = Path(os.path.realpath(__file__)).parent / 'install' / 'idabip_loader.py'
        shutil.copyfile(bip_plugin_loader, plugins_folder / 'idabip_loader.py')
        print(f'[+] Copied {bip_plugin_loader} -> {plugins_folder}')


setup(
    name='bip',
    version='0.1.0',
    packages=find_packages(include=['bip', 'bip.*']),
    cmdclass={
        'install': InstallBipPluginManager
    },
)
