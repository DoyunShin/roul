import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as fh:
    install_requires = fh.read().splitlines()

setuptools.setup(
    name="roul",
    version="0.1.3",
    author="DoyunShin",
    author_email="op@doyun.me",
    url="http://github.com/DoyunShin/roul",
    description="ROUL Library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10.0",
    install_requires=install_requires,
    # entry_points={
    #     "console_scripts": [
    #         "ptunnel = ptunnel.__main__:main",
    #     ]
    # },
)