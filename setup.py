#!/usr/bin/env python3

import sys
from cx_Freeze import setup, Executable

with open('README.rst') as readme_file:
    readme = readme_file.read()

# Dependencies are automatically detected, but it might need
# fine tuning.
buildOptions = {'packages': ['queue',
                             'idna.idnadata',
                             '_cffi_backend'],
                'include_files': [(sys.executable.replace(
                    'bin/python3',
                    'lib/python3.6/site-packages/.libs_cffi_backend/libffi-bce22613.so.6.0.4'),
                                   'lib/.libs_cffi_backend/libffi-bce22613.so.6.0.4')],
                'excludes': []}

base = 'Win32GUI' if sys.platform=='win32' else None

executables = [
    Executable('turtl-backup-gui.py', base=base)
]

setup(
    name='turtl-backup',
    options={'build_exe': buildOptions},
    executables=executables,
    version='0.0.4',
    description="Tool to backup a turtl account.",
    long_description=readme,
    author="Julien Palard",
    author_email='julien@palard.fr',
    url='https://github.com/JulienPalard/turtle-backup',
    entry_points={
        'console_scripts': [
            'turtl-backup=turtl_backup.turtl_backup:main',
            'turtl-backup-gui=turtl_backup.gui:main'
        ]
    },
    packages=['turtl_backup'],
    install_requires=[
        'requests',
        'cryptography'
    ],
    license="MIT",
    keywords='turtl backup',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
)
