.PHONY: test demo

test:
	python3 -m unittest discover -s tests -p 'test_*.py'

demo:
	python3 -m govcode_harness demo --output .runtime/first-slice
