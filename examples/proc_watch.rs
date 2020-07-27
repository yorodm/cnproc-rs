use cnproc::PidMonitor;

fn main() {
    let mut monitor = PidMonitor::new().unwrap();

    loop {
		match monitor.recv() {
			None => {},
			Some(x) => println!("{:?}", x)
		}
    }
}
