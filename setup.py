from setuptools import setup, find_packages

setup(
	# Application name:
	name="winsspi",

	# Version number (initial):
	version="0.0.1",

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsec.com",

	# Packages
	packages=find_packages(),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/skelsec/winsspi",

	zip_safe = True,
	#
	# license="LICENSE.txt",
	description="Windows SSPI library in pure Python",

	# long_description=open("README.txt").read(),
	python_requires='>=3.6',
	install_requires=[
		'minikerberos',
	],
	
	classifiers=(
		"Programming Language :: Python :: 3.6",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	),
)
