# Compile a PDF from the markdown files in the content directory
pdf-mac:
	@echo "\nCompiling PDF for macOS..."
	mkdir -p ./output
	pandoc content/*.md \
		--resource-path=.:./assets:./content \
		--pdf-engine=xelatex \
		--from=markdown+tex_math_single_backslash+tex_math_dollars+raw_tex \
		--to=latex \
		--filter mermaid-filter \
	  --citeproc \
		--bibliography=assets/bibliography.bib \
		--csl=assets/ieee.csl \
		--variable=fontsize=11pt \
		--variable=geometry:margin=1in \
		--variable=linkcolor:blue \
		--variable=monofont:DejaVuSansMono \
		--variable=monofontoptions:Scale=0.8 \
		--highlight-style=tango \
		--include-in-header=assets/titlepage.tex \
		--include-in-header=assets/code-format.tex \
		--include-in-header=assets/table-format.tex \
		--include-in-header=assets/footnote-format.tex \
		--output=./output/attestium-whitepaper.pdf
	cp ./output/attestium-whitepaper.pdf ../attestium-whitepaper.pdf
	@echo "Finished compiling PDF."
# Compile a PDF from the markdown files in the content directory
pdf:
	@echo "\nCompiling PDF..."
	mkdir -p ./output
	PUPPETEER_EXECUTABLE_PATH=$$(which chromium-browser || which chromium || which google-chrome) \
	pandoc content/*.md \
		--resource-path=.:./assets:./content \
		--pdf-engine=xelatex \
		--from=markdown+tex_math_single_backslash+tex_math_dollars+raw_tex \
		--to=latex \
		--filter mermaid-filter \
		--filter pandoc-citeproc \
		--bibliography=assets/bibliography.bib \
		--csl=assets/ieee.csl \
		--variable=fontsize=11pt \
		--variable=geometry:margin=1in \
		--variable=linkcolor:blue \
		--variable=monofont:DejaVuSansMono \
		--variable=monofontoptions:Scale=0.8 \
		--highlight-style=tango \
		--include-in-header=assets/titlepage.tex \
		--include-in-header=assets/code-format.tex \
		--include-in-header=assets/table-format.tex \
		--include-in-header=assets/footnote-format.tex \
		--output=./output/attestium-whitepaper.pdf
	cp ./output/attestium-whitepaper.pdf ../attestium-whitepaper.pdf
	@echo "Finished compiling PDF."
# Compile a LaTeX file from the markdown files in the content directory
latex:
	@echo "\nCompiling LaTeX file..."
	mkdir -p ./output
	PUPPETEER_EXECUTABLE_PATH=$$(which chromium-browser || which chromium || which google-chrome) \
	pandoc content/*.md \
		--resource-path=.:./assets:./content \
		--from=markdown+tex_math_single_backslash+tex_math_dollars+raw_tex \
		--to=latex \
		--filter mermaid-filter \
		--filter pandoc-citeproc \
		--bibliography=assets/bibliography.bib \
		--csl=assets/ieee.csl \
		--standalone \
		--variable=fontsize=11pt \
		--variable=geometry:margin=1in \
		--variable=linkcolor:blue \
		--variable=monofont:DejaVuSansMono \
		--variable=monofontoptions:Scale=0.8 \
		--highlight-style=tango \
		--include-in-header=assets/titlepage.tex \
		--include-in-header=assets/code-format.tex \
		--include-in-header=assets/table-format.tex \
		--include-in-header=assets/footnote-format.tex \
		--output=./output/attestium-whitepaper.tex
	@echo "Finished compiling LaTeX file."

watch:
	@make -s pdf || true
	@echo "Watching for changes..."
ifeq ($(shell uname -s),Darwin) # Use fswatch on macOS
	@fswatch -0 ./content/ | xargs -0 -n 1 -I {} make -s pdf-mac
else # Use inotifywait on Linux/WSL
	@inotifywait -r -m -e modify ./content/ | \
	while read file_path file_event file_name; do  \
		make -s pdf; \
	done
endif
# Count the words in the markdown files, excluding files starting with 00 or 9*
wordcount:
	@cd content && find . -name "*.md" | grep -v -E "(00|9[0-9])-" | sort | xargs wc -w

clean:
	rm -rf ./output

.PHONY: pdf pdf-mac latex watch wordcount clean
