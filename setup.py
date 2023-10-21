from setuptools import setup, find_packages
from setuptools.command.install import install
from pathlib import Path
import sys
import os
import shutil
from distutils.dir_util import copy_tree
import typing
import re


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
    
    def _wrap_rcfile_content(self, rcfile_content: str) -> str:
        head = '# --- bip start ---'
        tail = '# --- bip end ---'
        return f'{head}\n{rcfile_content}\n{tail}'
    
    def _update_rcfile(self, source: Path, destination: Path):
        with open(source, 'r') as source_rcfile:
            source_data = source_rcfile.read()

        if not destination.exists():
            with open(destination, 'w') as destination_rcfile:
                destination_rcfile.write(self._wrap_rcfile_content(source_data))
                destination_rcfile.write('\n')
            
            print(f'[+] Created {destination}')
            return
        
        with open(destination, 'r') as destination_rcfile:
            destination_data = destination_rcfile.read()

        head = '# --- bip start ---'
        tail = '# --- bip end ---'
        updated = re.sub(f'{head}(.*){tail}',
                         f'{head}\n{source_data}\n{tail}',
                         destination_data,
                         flags=re.DOTALL)
        
        with open(destination, 'w') as destination_rcfile:
            destination_rcfile.write(updated)
            
        print(f'[+] Updated {destination}')

    def _setup_idapythonrc(self):
        print('[+] Setting up idapythonrc.py')
        idapythonrc_path = self._get_ida_folder() / 'idapythonrc.py'
        ipyidarc_path = self._get_ida_folder() / 'ipyidarc.py'

        install_folder = Path(os.path.realpath(__file__)).parent / 'install'
        install_idapythonrc_path = install_folder / 'idapythonrc.py'
        install_ipyidarc_path = install_folder / 'ipyidarc.py'

        self._update_rcfile(install_idapythonrc_path, idapythonrc_path)
        self._update_rcfile(install_ipyidarc_path, ipyidarc_path)

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
