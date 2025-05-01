# Main document name (without extension)
TEX = report

# Tools
LATEX = pdflatex
BIBER = biber

# Flags
LATEXFLAGS = -interaction=nonstopmode -halt-on-error

.PHONY: all clean

all: $(TEX).pdf

# If you don't yet have a refs.bib, make an empty one:
# refs.bib:
# 	@test -f refs.bib || echo "% dummy bibliography file" > refs.bib

# Build sequence: LaTeX → Biber → LaTeX ×2
$(TEX).pdf: $(TEX).tex report_style.sty refs.bib
	@echo "==> Running pdflatex pass 1"
	$(LATEX) $(LATEXFLAGS) $(TEX).tex
	@echo "==> Running biber"
	$(BIBER) $(TEX) || true
	@echo "==> Running pdflatex pass 2"
	$(LATEX) $(LATEXFLAGS) $(TEX).tex
	@echo "==> Running pdflatex pass 3"
	$(LATEX) $(LATEXFLAGS) $(TEX).tex

clean:
	@echo "==> Cleaning auxiliary files"
	rm -f \
	  $(TEX).aux \
	  $(TEX).bbl \
	  $(TEX).bcf \
	  $(TEX).blg \
	  $(TEX).fdb_latexmk \
	  $(TEX).fls \
	  $(TEX).log \
	  $(TEX).out \
	  $(TEX).run.xml \
	  $(TEX).toc \
	  $(TEX).pdf \
	  refs.bib
