use std::sync::{mpsc, Arc};

use crate::{ffi::proto::Account, gdk_ses::GdkSes, worker};

pub type ResCallback = Box<dyn FnOnce(&mut worker::Data) + Send>;

pub enum Event {
    Run(ResCallback),
}

pub type EventCallback = Arc<dyn Fn(Account, Event) + Send + Sync>;

pub fn callback<Resp, WalletCallback, ResCallback>(
    account: Account,
    worker: &mut super::Data,
    wallet_cb: WalletCallback,
    res_cb: ResCallback,
) where
    Resp: Send + 'static,
    WalletCallback: FnOnce(&dyn GdkSes) -> Result<Resp, anyhow::Error> + Send + Sync + 'static,
    ResCallback: FnOnce(&mut super::Data, Result<Resp, anyhow::Error>) + Send + Sync + 'static,
{
    let wallet = match worker.get_wallet(account) {
        Ok(wallet) => wallet,
        Err(err) => {
            res_cb(worker, Err(err));
            return;
        }
    };

    let event_callback = Arc::clone(&worker.wallet_event_callback);

    // TODO: Use a thread pool
    std::thread::spawn(move || {
        let res = wallet_cb(wallet.as_ref());
        event_callback(
            account,
            Event::Run(Box::new(move |data| {
                res_cb(data, res);
            })),
        );
    });
}

#[must_use]
pub fn send_wallet<Resp, WalletCallback>(
    wallet: &Arc<dyn GdkSes>,
    wallet_cb: WalletCallback,
) -> mpsc::Receiver<Result<Resp, anyhow::Error>>
where
    Resp: Send + 'static,
    WalletCallback: FnOnce(&dyn GdkSes) -> Result<Resp, anyhow::Error> + Send + Sync + 'static,
{
    let (resp_sender, resp_receiver) = mpsc::channel::<Result<Resp, anyhow::Error>>();

    let wallet = Arc::clone(wallet);

    // TODO: Use a thread pool
    std::thread::spawn(move || {
        let res = wallet_cb(wallet.as_ref());
        resp_sender.send(res).expect("channel must be open");
    });

    resp_receiver
}
