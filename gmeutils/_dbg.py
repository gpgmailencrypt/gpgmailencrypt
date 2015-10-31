from   functools			import wraps
#####
#_dbg
#####

def _dbg(func):
	@wraps(func)
	def wrapper(*args, **kwargs):
		parent=None

		if args:
			if hasattr(args[0],"debug"):
				parent=args[0]

		if not parent:
			return func(*args,**kwargs)

		lineno=0
		endlineno=0

		try:
			source=inspect.getsourcelines(func)
			lineno=source[1]
			endlineno=lineno+len(source[0])
		except:
			pass

		parent.debug("START %s"%func.__name__,lineno)
		if hasattr(parent,"_level"):
			parent._level+=1
	
		result=func(*args,**kwargs)
		if hasattr(parent,"_level"):
			parent._level-=1

			if parent._level<0:
				parent._level=0

		parent.debug("END %s"%func.__name__,endlineno)
	

		return result

	return wrapper

