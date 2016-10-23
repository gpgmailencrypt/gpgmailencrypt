#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
from .child 	import _gmechild
import threading
import time

#########
#_mytimer
#########

class _mytimer(_gmechild):
	"""
	Timer class that can act either as a countdown timer or a periodic revolving
	timer.

	The class will return timer.is_running() == False in case the timer expired.
	Additionally you can set a your own alarmfunction to do whatever you want
	when the timer is fired.


	case 1: A countdown timer

	timer.set_timer(10,60)

	(10 times multiplicated with 60 seconds = 10 minutes)
	will be called once after 10 minutes


	case 2: a revolving timer

	timer.set_timer(0,600,your_alarmfunction)
	will  your_alarmfunction every 600 seconds


	case 3: A timer to check for inactivity

	To get a timer to check inactivity you can do the following:

	mytimer.start(10,60)

	and then in your useraction function call timer.set_alive() in case of
	user activity.
	To check if the the timer already expired check timer.is_running()
	"""

	def __init__(self,parent=None):
		_gmechild.__init__(self,parent,filename=__file__)
		self.counter=0
		self.alarmtime=10
		self.timer=1
		self.running=False
		self.alarmfunc=None
		self.alarmfuncargs=[]
		self.kwalarmfuncargs={}

	########
	#_action
	########

	def _action(self):

		if self.counter==1:
			self._alert()
		else:

			if self.counter>0:
				self.counter-=1
			else:

				if self.alarmfunc:
					self.alarmfunc(*self.alarmfuncargs,**self.kwalarmfuncargs)

			self._create_timer()

	#######
	#_alert
	#######

	def _alert(self):

		if self.alarmfunc:
			self.alarmfunc(*self.alarmfuncargs,**self.kwalarmfuncargs)

		self.running=False

	##############
	#_create_timer
	##############

	def _create_timer(self):
		self.alarm=threading.Timer( self.timer,
									self._action)
		self.running=True
		self.alarm.start()


	###########
	#is_running
	###########

	def is_running(self):
		"""returns True if the timer is running,
		returns False after the timer expired"""
		return self.running

	##########
	#set_alive
	##########

	def set_alive(self):
		"""
		if the timer is running it increases the duration of the alarm to its
		original start alarmtime.
		if the timer isn't running, this function has no effect.
		"""
		self.counter=self.alarmtime

	######
	#start
	######

	def start(  self,
				alarmtime=10,
				timerinterval=1,
				alarmfunction=None,
				alarmargs=(),
				kwalarmargs={}):
		"""
		The timer will be fired after "alarmtime" multiplicated with
		"timerintervall" in seconds.

		if alarmtime is set to 0, it will be an eternal loop, until stop()
		is called.You have to set a user defined alarmfunction to use this
		option.

		alarmargs and kwalarmargs are the values for the user defined alarm
		function.
		"""
		self.alarmtime=alarmtime
		self.timer=timerinterval
		self.alarmfunc=alarmfunction
		self.alarmfuncargs=alarmargs
		self.kwalarmfuncargs=kwalarmargs
		self.counter=self.alarmtime
		self._create_timer()

	#####
	#stop
	#####

	def stop(self):
		"stops a running timer"
		self.alarm.cancel()
		self.running=False


