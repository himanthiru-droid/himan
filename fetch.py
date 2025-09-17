import os
import pandas as pd
import pyotp
import requests
import streamlit as st
from dotenv import load_dotenv
from SmartApi import SmartConnect
from logzero import logger
from datetime import datetime

# Streamlit app title
st.title("Angel One NIFTY Option Chain Fetcher")

# Load env variables
load_dotenv()
APIKEY = os.getenv("APIKEY")
CLIENTID = os.getenv("CLIENTID")
PASSWORD = os.getenv("PASSWORD")
MPIN = os.getenv("MPIN")
TOTPSECRET = os.getenv("TOTPSECRET")

if not all([APIKEY, CLIENTID, PASSWORD, MPIN, TOTPSECRET]):
    st.error("Please set all required environment variables: APIKEY, CLIENTID, PASSWORD, MPIN, TOTPSECRET")
    st.stop()

@st.cache_data(show_spinner=False)
def generate_session():
    try:
        totp = pyotp.TOTP(TOTPSECRET).now()
        smartApi = SmartConnect(APIKEY)
        data = smartApi.generateSession(CLIENTID, PASSWORD, totp)
        if not data["status"]:
            logger.error(f"Login failed: {data}")
            return None, "Login failed"
        logger.info("Login successful")
        return smartApi, None
    except Exception as e:
        logger.exception(f"Login error: {e}")
        return None, str(e)

@st.cache_data(show_spinner=False)
def download_instruments():
    url = "https://margincalculator.angelbroking.com/OpenAPIFile/files/OpenAPIScripMaster.json"
    st.info("Downloading instruments file...")
    resp = requests.get(url)
    instruments = pd.DataFrame(resp.json())
    return instruments

def fetch_option_chain(smartApi, instruments):
    st.info("Fetching option chain data...")
    nifty_spot = instruments[(instruments["symbol"] == "NIFTY") & (instruments["exchSeg"] == "NSE")]
    if nifty_spot.empty:
        st.error("NIFTY spot token not found in instruments")
        return None
    nifty_spot_token = nifty_spot.iloc[0]["token"]
    ltpdata = smartApi.ltpData("NSE", "NIFTY", nifty_spot_token)
    spotprice = float(ltpdata["data"]["ltp"])
    st.write(f"NIFTY Spot Price: {spotprice}")

    atm_strike = round(spotprice / 50) * 50
    strikes = [atm_strike - 50, atm_strike, atm_strike + 50]
    st.write(f"ATM strikes considered: {strikes}")

    nifty_options = instruments[(instruments["name"].str.startswith("NIFTY")) & (instruments["instrumenttype"] == "OPTIDX")].copy()
    nifty_options["expiry"] = pd.to_datetime(nifty_options["expiry"], errors='coerce')
    nearest_expiry = nifty_options["expiry"].min()
    st.write(f"Nearest expiry: {nearest_expiry.date()}")

    filtered = nifty_options[(nifty_options["expiry"] == nearest_expiry) & (nifty_options["strike"].astype(float).isin(strikes))]
    filtered["ltp"] = None

    for idx, row in filtered.iterrows():
        try:
            token = row["token"]
            tsymbol = row["symbol"]
            ltp_data = smartApi.ltpData("NFO", tsymbol, token)
            filtered.at[idx, "ltp"] = ltp_data["data"]["ltp"]
            st.write(f"{row['optiontype']} {row['strike']} LTP: {ltp_data['data']['ltp']}")
        except Exception as e:
            st.error(f"Failed to fetch LTP for {row['symbol']} {row['strike']} {row['optiontype']}: {e}")

    return filtered

def main():
    st.write("Press the button to fetch the latest NIFTY option chain data and save it to a CSV file.")

    if st.button("Fetch Option Chain"):
        smartApi, err = generate_session()
        if smartApi is None:
            st.error(f"Login failed: {err}")
            return

        instruments = download_instruments()
        filtered = fetch_option_chain(smartApi, instruments)

        if filtered is not None:
            csv_filename = "nifty_option_chain.csv"
            filtered.to_csv(csv_filename, index=False)
            st.success(f"Option chain data saved to {csv_filename}")
            st.dataframe(filtered)

        try:
            smartApi.terminateSession(CLIENTID)
            st.info("Logged out successfully.")
        except Exception as e:
            st.warning(f"Logout failed: {e}")

if __name__ == "__main__":
    main()
