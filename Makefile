requirements:
	pip install -rrequirements.txt

version:
	git describe --tags > $@

ext:
	mkdir -p $@

ext/inql_burp.py: requirements ext version
	stickytape inql/burp_ext.py --add-python-path . > $@
	sed -i.bak "s/%%VERSION%%/$$(cat version)/g" $@
	rm $@.bak

clean:
	rm -rf ext

.PHONY: clean version
