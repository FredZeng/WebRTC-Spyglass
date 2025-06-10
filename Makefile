.PHONY: macapp winexe clean

macapp:
	pyinstaller --windowed --onefile --noconsole --name WebRTC-Spyglass main.py

winexe:
	pyinstaller --windowed --onefile --noconsole --name WebRTC-Spyglass.exe main.py

clean:
	rm -rf build dist __pycache__ *.spec