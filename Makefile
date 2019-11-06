requirements:
	pip install -rrequirements.txt

ext:
	mkdir -p $@

ext/inql_burp.py: requirements ext
	stickytape inql/burp_ext.py --add-python-path . > $@

clean:
	rm -rf ext
