requirements:
	pip install -r requirements.txt

version:
	python3 setup.py generate_version

ext:
	mkdir -p $@

ext/inql_burp.py: requirements ext version
	stickytape inql/burp_loader.py --add-python-path . > $@

clean:
	rm -rf ext

package: version
	python2 setup.py sdist bdist_wheel
	python3 setup.py sdist bdist_wheel

test_upload: package
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*

upload: package
	twine upload dist/*

.PHONY: clean version upload package
