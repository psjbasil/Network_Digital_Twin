from setuptools import setup, find_packages

setup(
    name="network_digital_twin",
    version="1.0.0",
    description="Real-time network topology visualization system with SDN controller",
    author="Network Digital Twin Team",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        'flask>=2.0.0',
        'flask-socketio>=5.0.0',
        'networkx>=2.5',
        'matplotlib>=3.3.0',
        'requests>=2.25.0',
        'ryu>=4.34'
    ],
    extras_require={
        'dev': [
            'pytest>=6.0.0',
            'pytest-cov>=2.0.0',
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: System :: Networking",
        "Topic :: Scientific/Engineering :: Visualization",
    ],
) 