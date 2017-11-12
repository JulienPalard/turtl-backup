#!/usr/bin/env python3

from setuptools import setup

with open('README.rst') as readme_file:
    readme = readme_file.read()


setup(
    name='turtl-backup',
    version='0.0.4',
    description="Tool to backup a turtl account.",
    long_description=readme,
    author="Julien Palard",
    author_email='julien@palard.fr',
    url='https://github.com/JulienPalard/turtle-backup',
    entry_points={
        'console_scripts': [
            'turtl-backup=turtl_backup.turtl_backup:main'
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
