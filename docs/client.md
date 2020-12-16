# BBRF Client

Once you have a bbrf server up and running, go ahead and clone this repository.

  * `git clone https://github.com/honoki/bbrf-client`
  * `cd bbrf-client`
  * `virtualenv --python=python3 .env && source .env/bin/activate && pip install -r requirements.txt`

## Setup

Register the function `bbrf` in your `.bash_profile` (or whichever shell you use):

```bash
function bbrf() {
        source ~/bbrf-client/.env/bin/activate;
        python ~/bbrf-client/bbrf.py "$@"
        deactivate
}
```

## Configuration

Create a file `~/.bbrf/config.json` with the required configuration:

```json
{
    "username": "bbrf",
    "password": "<your secure password>",
    "couchdb": "https://<your-instance>:6984/bbrf",
    "slack_token": "<a slack token to receive notifications>"
}
```