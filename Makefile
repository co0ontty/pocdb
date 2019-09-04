check:
	virtualenv .testenv --no-download
	.testenv/bin/pip install -r requirements.txt
	.testenv/bin/nosetests -v --with-doctest
	rm -rf .testenv

