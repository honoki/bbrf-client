import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="bbrf",
    version="1.1.0",
    author="@honoki",
    author_email="pieter@honoki.net",
    description="The client component of the Bug Bounty Reconnaissance Framework (BBRF)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/honoki/bbrf-client",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=['docopt', 'requests', 'slackclient==1.3.2'],
    python_requires='>=3.5',
    entry_points = {
        'console_scripts': ['bbrf=bbrf.bbrf:main'],
    }
)
