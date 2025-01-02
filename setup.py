from setuptools import setup, find_packages

setup(
    name="network_digital_twin",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'flask',
        'flask-socketio',
        'networkx',
        'matplotlib',
        'requests',
        'ryu'
    ],
) 