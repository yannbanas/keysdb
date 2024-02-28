import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="keysdb",
    version="0.0.1",
    author="Banas Yann",
    author_email="yannbanas@gmail.com",
    description="A simple in-memory key-value store with data persistence and multiple data types support.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yannbanas/keysdb",
    packages=setuptools.find_packages(where="src"),
    package_dir={'': 'src'},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
