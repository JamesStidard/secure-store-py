init:
	pip install -r requirements.txt
	pip install -e .
test:
	py.test tests
