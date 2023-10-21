from setuptools import setup, find_packages
from setuptools.command.install import install
from pathlib import Path
import sys
import os
import shutil
from distutils.dir_util import copy_tree
import typing


class InstallBipPluginManager(install):
    def _get_ida_folder(self):
        if os.getenv('IDAUSR') is not None:
            return Path(os.getenv('IDAUSR'))
        elif sys.platform in ("linux", "linux2", "darwin"):
            return Path(os.getenv('HOME')) / '.idapro'
        elif sys.platform == "win32":
            return Path(os.getenv('APPDATA')) / 'Hex-Rays' / 'IDA Pro'
        
        raise RuntimeError('Unknwown OS do not know where to install')
    
    def _setup_bip_plugin(self):
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
    
    def _get_bip_rcfile_version(self, rcfile_content: str) -> typing.Optional[str]:
        for line in rcfile_content.split('\n'):
            if '_BIP_IDAPYTHON_RC_VERSION' not in line:
                continue
            
            return line.split('=')[1].strip()[1:-1]
        
        return None

    def _setup_idapythonrc(self):
        print('[+] Setting up idapythonrc.py')
        idapythonrc_path = self._get_ida_folder() / 'idapythonrc.py'

        if not idapythonrc_path.exists():
            idapythonrc_path.touch()
       
        bip_idapythonrc_path = Path(os.path.realpath(__file__)).parent / 'install' / 'idapythonrc.py'
        with open(bip_idapythonrc_path, 'r') as bip_rcfile:
            bip_idapythonrc_content = bip_rcfile.read()
        
        install_rcfile_version = self._get_bip_rcfile_version(bip_idapythonrc_content)

        with open(idapythonrc_path, 'r') as rcfile:
            existing_rcfile_version = self._get_bip_rcfile_version(rcfile.read())
        
        if existing_rcfile_version is None or install_rcfile_version > existing_rcfile_version:
            with open(idapythonrc_path, 'a') as rcfile:
                rcfile.write('\n')
                rcfile.write(bip_idapythonrc_content)
                rcfile.write('\n')
            print('[+] Populated idapythonrc.py')
        

    def run(self):
        install.run(self)
        self._setup_bip_plugin()
        self._setup_idapythonrc()


setup(
    name='bip',
    version='0.1.0',
    packages=find_packages(include=['bip', 'bip.*']),
    cmdclass={
        'install': InstallBipPluginManager
    },
)
