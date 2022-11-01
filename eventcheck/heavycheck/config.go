package heavycheck

//定义配置结构体
type Config struct {
	//队列里面最大的任务数
	MaxQueuedTasks int // the maximum number of tasks to queue up
	//线程数
	Threads int
}

//定义默认配置
func DefaultConfig() Config {
	return Config{
		MaxQueuedTasks: 1024, //队列里面初始化默认最多1024个任务，0个线程
		Threads:        0,
	}
}
