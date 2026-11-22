///|
// @fs.walk 回调语义：(dir_path, entries_in_dir)
// 第 1 个参数是目录，文件列表在第 2 个参数中
async test "T6a: @fs.walk recursion with exclude" {
  let root = "./fixture"
  let collected : Array[String] = []
  @fs.walk(root, (dir, entries) => {
    for name in entries {
      collected.push("\{dir}/\{name}")
    }
  }, exclude=(p) => p.contains(".git") || p.contains("_build")) catch {
    e => abort("walk failed: \{e}")
  }
  collected.sort()
  assert_true(collected.length() == 4)
}

///|
// Semaphore 的 Bounded Concurrency 场景：限制同时进入临界区的任务数
async test "T6b: semaphore bounds concurrency" {
  let sem = @semaphore.Semaphore(2)
  let log : Array[String] = []
  @async.with_task_group <| group => {
    for i in 0..<6 {
      group.spawn_bg() <| () => {
        sem.acquire()
        defer sem.release()
        log.push("enter \{i}")
        @async.sleep(5)
        log.push("leave \{i}")
      }
    }
  }
  assert_true(log.length() == 12)
  assert_true(log[0] == "enter 0")
  assert_true(log[1] == "enter 1")
  assert_true(log[2] == "leave 0" || log[2] == "leave 1")
}
