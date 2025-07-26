use std::process::Command;

pub fn get_first_available_uid(start_uid: libc::uid_t) -> libc::uid_t {
    let mut uid = start_uid;
    loop {
        // Check if UID is taken
        // SAFETY: linux systems must have getent
        let status = Command::new("getent")
            .arg("passwd")
            .arg(uid.to_string())
            .status()
            .unwrap();

        // 2 -> not found in database
        if status.code().is_some_and(|c| c == 2) {
            break;
        }

        uid += 1;
    }
    uid
}
