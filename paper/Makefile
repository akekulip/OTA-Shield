PY ?= python3
REPO = $(abspath ..)

.PHONY: all numbers figures paper clean

all: numbers figures paper

numbers:
	$(PY) $(REPO)/experiments/extract_paper_numbers.py \
		--agg-dir $(REPO)/runs/experiments/_agg \
		--out numbers.tex

figures:
	$(MAKE) -C $(REPO)/experiments aggregate figures

paper: numbers
	pdflatex -interaction=nonstopmode main.tex
	bibtex main || true
	pdflatex -interaction=nonstopmode main.tex
	pdflatex -interaction=nonstopmode main.tex
	@grep -c '\\?\\?' main.pdf 2>/dev/null && \
		echo "WARNING: ?? placeholders remain — experiments incomplete" || true

clean:
	rm -f main.{aux,bbl,blg,log,out,pdf} numbers.tex
