#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
from   	functools			import wraps
import 	inspect
import 	os
from	.					import child

#####
#_dbg
#####

def _dbg(func):

	@wraps(func)
	def wrapper(*args, **kwargs):
		parent=None

		if args:

			if isinstance(args[0],child._gmechild):
				parent=args[0]
			elif hasattr(args[0],"send_mails"):
				parent=args[0]
			elif hasattr(args[0],"parent"):
				parent=args[0].parent

		if not parent:
			print(">> START %s"%func.__name__,lineno)
			result=func(*args,**kwargs)
			print(">> END %s"%func.__name__,lineno)
			return result

		lineno=0
		endlineno=0
		filename=inspect.getfile(func)

		try:
			source=inspect.getsourcelines(func)
			lineno=source[1]
			endlineno=lineno+len(source[0])
		except:
			pass

		if hasattr(parent,"_level"):
			parent._level+=1

		parent.debug("START %s"%func.__name__,lineno,filename)
		result=func(*args,**kwargs)
		parent.debug("END %s"%func.__name__,endlineno,filename)

		if hasattr(parent,"_level"):
			parent._level-=1

			if parent._level<0:
				parent._level=0

		return result

	return wrapper

