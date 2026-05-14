.PHONY: test smoke

test:
	PYTHONPATH=src python3 -m unittest discover -s tests

smoke:
	PYTHONPATH=src python3 -m forgeflag.cli --db .forgeflag/notebook.sqlite init
	PYTHONPATH=src python3 -m forgeflag.cli --db .forgeflag/notebook.sqlite add-challenge web-01 --category web --target http://127.0.0.1:8080 --tag login
	PYTHONPATH=src python3 -m forgeflag.cli --db .forgeflag/notebook.sqlite run web-01 --allow-host 127.0.0.1
	PYTHONPATH=src python3 -m forgeflag.cli --db .forgeflag/notebook.sqlite findings web-01
