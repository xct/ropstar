# Plugins

Plugins will be called after obtaining a shell and can be used for various things, for example post-exploitation.

Plugin template:
```
class Plugin:
	def __init__(self, home):
		self.home = home
		pass

	def run(self, p):
		pass
``` 

In addition you will need an `__init__.py` file that imports your plugin here.