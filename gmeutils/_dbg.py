from   functools			import wraps
import inspect
#####
#_dbg
#####

def _dbg(func):

	@wraps(func)
	def wrapper(*args, **kwargs):
		parent=None

		if args:

			if hasattr(args[0],"parent"):
				parent=args[0].parent
			elif hasattr(args[0],"debug"):
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

		if hasattr(parent,"_level"):
			parent._level+=1

		parent.debug("START %s"%func.__name__,lineno)
		result=func(*args,**kwargs)
		parent.debug("END %s"%func.__name__,endlineno)

		if hasattr(parent,"_level"):
			parent._level-=1

			if parent._level<0:
				parent._level=0

		return result

	return wrapper

