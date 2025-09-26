use clap::Parser;
use std::fmt::Debug;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;
use std::process::Command;
use tokio;
use tokio::sync::mpsc::{channel, Sender, Receiver};
use colored::Colorize;

#[derive(Parser, Debug)]
#[command(version, about, long_about = Some("finds shares, but its written in rust which sometimes gets past EDR!"))]
struct Args{
    #[arg(short, long, help = "path to save output file Defaults to not saving output.")]
    outfile: Option<PathBuf>,

    #[arg(short, long, help = "number of threads to use, default to 10.")]
    threads: Option<usize>,

    #[arg(short, long, help = "specific targets. should be comma separated.")]
    targets: Option<String>,
}

struct ShareFinder{
    id: usize,
    tx: Sender<String>,
}

async fn find_shares(task: ShareFinder, mut rx: Receiver<String>){
    println!("{} started!", task.id);
    task.tx.send(format!("{}:READY!", task.id)).await.unwrap();
    loop{
        let rx_res = rx.recv().await;
        if rx_res.is_some(){
            let computer = rx_res.unwrap();
            if computer == String::from("||DONE||"){
                task.tx.send(format!("{}:||DONE||", task.id)).await.unwrap();
                break;
            }
            println!("scanning {}", computer);
            let share_list_res = Command::new("net").arg("view").arg(computer.clone()).arg("/all").output();
            let mut error_string = String::new();
            let mut success_string = String::new();
            if share_list_res.is_ok(){
                let output = share_list_res.unwrap();
                if output.stdout.len() > 0{
                    success_string = String::from_utf8_lossy(&output.stdout).to_string();
                }

                if output.stderr.len() > 0{
                    error_string = String::from_utf8_lossy(&output.stderr).to_string();
                }
            }
            else{
                error_string = share_list_res.err().unwrap().to_string();
            }
            if error_string.len() > 0{
                eprintln!("{}", "Error listing shares!".red());
                eprint!("{}", error_string.red());
            }
            else if success_string.len() > 0{
                for line in success_string.lines(){
                    if line.contains("Disk"){
                        let share_name = line.split_whitespace().collect::<Vec<&str>>()[0];
                        let share_path = format!("\\\\{}\\{}", computer, share_name);
                        task.tx.send(format!("{}:{}", task.id, share_path)).await.unwrap();
                    }
                }
            }
        }
    }
}



#[tokio::main]
async fn main(){
    print!{"
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡿⠋⠁⠙⠿⠿⠟⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡿⠁⠀⢀⣴⣾⣷⣦⡀⠀⠈⠉⠉⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⡇⠀⠀⠀⠀⢸⣿⣿⣿⣿⡇⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣧⣤⣤⣄⠀⠈⠛⠿⠿⠋⠀⠀⣰⡿⠿⣿⣿⣿⣿⠁⠀⠀⢸⣿⣿⣿⣿⠿⣿
⣿⣿⣿⣿⣿⠁⠀⠀⢀⣀⡀⠀⠀⠈⠀⠀⠘⣿⠿⠿⠀⠀⠀⠸⠿⢿⣿⠃⠀⣿
⣿⣿⣿⣿⣇⣀⠀⢀⣿⣿⣿⣄⣀⣴⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿
⣿⣿⣿⣿⣿⣿⣿⣾⡿⠋⠛⠿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⠀⠀⠀⠀⠀⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⣿
⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⣿
⣿⣿⣿⣿⣿⣿⣧⣤⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣤⣤⣤⣤⣤⣤⣤⣤⣽⣿⣿⣿⣿⣭⣤⣤⣤⣤⣿

                                                                                        
 (  (         (                         )                                               
 )\\))(   '  ( )\\          )     (    ( /(                                               
((_)()\\ )  ))((_)(  (    (     ))\\   )\\())(                                             
_(())\\_)()/((_)  )\\ )\\   )\\  '/((_) (_))/ )\\                                            
\\ \\((_)/ (_))| |((_|(_)_((_))(_))   | |_ ((_)                                           
 \\ \\/\\/ // -_) / _/ _ \\ '  \\() -_)  |  _/ _ \\                                           
  \\_/\\_/ \\___|_\\__\\___/_|_|_|\\___|   \\__\\___/                                           
  *   )        )                             )                                          
` )  /(  (  ( /(   )         (            ( /(    ) (     (        (    )  (            
 ( )(_))))\\ )\\()| /(  (     ))\\ (      (  )\\())( /( )(   ))\\(     ))\\( /( ))\\           
(_(_())/((_|_))/)(_)) )\\ ) /((_))\\     )\\((_)\\ )(_)|()\\ /((_)\\   /((_)\\())((_)          
|_   _(_)) | |_((_)_ _(_/((_))(((_)   ((_) |(_|(_)_ ((_|_))((_) (_))((_)(_))            
  | | / -_)|  _/ _` | ' \\)) || (_-<   (_-< ' \\/ _` | '_/ -_|_-<_/ -_) \\ / -_)           
  |_| \\___| \\__\\__,_|_||_| \\_,_/__/___/__/_||_\\__,_|_| \\___/__(_)___/_\\_\\___|(          
   (             )   )           |___(_|         )       )    )\\ )         ) )\\ )    )  
   )\\      (  ( /(( /(     (       ( )\\   (   ( /( ||_( /(   (()/((     ( /((()/( ( /(  
((((_)(   ))\\ )\\())\\()) (  )(      )((_) ))\\  )\\()|_-<)\\())   /(_))\\ )  )\\())/(_)))\\()) 
 )\\ _ )\\ /((_|_))((_)\\  )\\(()\\ _  ((_)_ /((_)((_)\\/ _(_))/   (_))(()/( ((_)\\(_)) ((_)\\  
 (_)_\\(_|_))(| |_| |(_)((_)((_|_)  | _ |_))(| | (_)||| |_    | _ \\)(_)) | (_) _ \\/  (_) 
  / _ \\ | || |  _| ' \\/ _ \\ '_|_   | _ \\ || |_  _|   |  _|   |  _/ || |_  _||   / () |  
 /_/ \\_\\ \\_,_|\\__|_||_\\___/_| (_)  |___/\\_,_| |_|     \\__|___|_|  \\_, | |_| |_|_\\\\__/   
                                                        |_____|   |__/                  
 
    "}
    let args = Args::parse();
    let mut outfile = PathBuf::new();
    let mut threads = 10;
    let mut save = false;
    let mut computers = Vec::new();
    if args.outfile.is_some(){
        outfile = args.outfile.unwrap();
        save = true;
    }
    if args.threads.is_some(){
        threads = args.threads.unwrap();
    }
    if args.targets.is_some(){
        println!("gathering the targets you gave me.");
        let targets = args.targets.unwrap();
        if targets.contains(","){
            let split_targets: Vec<&str> = targets.split(",").collect();
            for target in split_targets{
                computers.push(target.to_string());
            }
        }
        else{
            computers.push(targets);
        }
    }
    else{
        println!("no targets given, proceeding with domain computer enumeration...");
        println!("finding computers...");
        let command_string = String::from("net group \"domain computers\" /domain");
        let mut temp_file = fs::File::create("./temp.bat").unwrap();
        write!(temp_file, "{}", command_string).unwrap();
        let computer_res = Command::new(".\\temp.bat").output();
        let mut error_string = String::new();
        let mut success_string = String::new();
        fs::remove_file("./temp.bat").unwrap();
        if computer_res.is_ok(){
            let output = computer_res.unwrap();
            if output.stdout.len() > 0{
                success_string = String::from_utf8_lossy(&output.stdout).to_string();
            }
            else if output.stderr.len() > 0{
                error_string = String::from_utf8_lossy(&output.stderr).to_string();
            }
        }
        else{
            error_string = computer_res.err().unwrap().to_string();
        }
        if error_string.len() > 0{
            eprintln!("{}", "error getting computers!".red());
            eprintln!("{}", error_string.red());
            exit(1);
        }
        if success_string.len() > 0{
            for line in success_string.lines(){
                if line.contains("$"){
                    let words:Vec<&str> = line.split_whitespace().collect();
                    for word in words{
                        let mut computer_name = word.to_string();
                        computer_name.pop();
                        println!("{} {}", "found".green(), computer_name.green());
                        computers.push(computer_name);
                    }
                }
            }
        }
    }
    println!("computer enumeration finished, starting task finder threads...");
    if threads > computers.len(){
        threads = computers.len();
    }
    let (maintx, mut mainrx) = channel(1024);
    let mut tasks = Vec::new();
    let mut task_txes = Vec::new();
    for id in 0..threads{
        let (tx,rx) = channel(1);
        let new_task = ShareFinder{id, tx: maintx.clone()};
        let new_thread = tokio::spawn(find_shares(new_task, rx));
        tasks.push(new_thread);
        task_txes.push(tx.clone());
    }
    let mut ready = 0;
    let mut current_computer = 0;
    let mut finished = false;
    let mut done_threads = 0;
    loop {
        if done_threads == threads{
            break;
        }
        if !mainrx.is_empty(){
            let rx_res = mainrx.recv().await;
            if rx_res.is_some(){
                let message = rx_res.unwrap();
                let message_parts: Vec<&str> = message.split(":").collect();
                let _id: usize = message_parts[0].parse().unwrap();
                let content = message_parts[1];
                match content{
                    "READY!" => {
                        ready += 1;
                    }
                    "||DONE||" => {
                        done_threads += 1;
                    }
                    _ => {println!("{}", content.green());
                        if save{
                            let open_res = OpenOptions::new().append(true).create(true).open(&outfile);
                            if open_res.is_ok(){
                                let mut file = open_res.unwrap();
                                let write_res = write!(file, "{}\n", content);
                                if write_res.is_err(){
                                    eprintln!("{}", "error writing to outfile!".red());
                                    eprintln!("{}", write_res.err().unwrap().to_string().red());
                                }
                            }
                        }
                    }
                }
            }
        }
        if ready == threads{
            let mut sent = false;
            if !finished{
                for tx in &task_txes{
                    if tx.capacity() > 0{
                        tx.send(computers[current_computer].clone()).await.unwrap();
                        sent = true;
                        break;
                    }
                }
                if sent{
                    current_computer +=1;
                    if current_computer == computers.len() {
                        finished = true;
                    }
                }
            }
        }
        if finished{
            for tx in &task_txes{
                let send_res = tx.send(String::from("||DONE||")).await;
                if send_res.is_ok(){
                    send_res.unwrap();
                }
            }
        }
    }
}
