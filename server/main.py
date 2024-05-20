from datetime import datetime, timedelta, timezone
from typing import Annotated, Union
from pathlib import Path
from typing import List



from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import json
import random

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()
origins = [
    "http://localhost:3007",  # React dev server
    # Add other origins as needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]

@app.get("/songs")
async def get_songs():
    # Define the path to the songs.json file
    songs_json_path = "data/songs.json"
    # Check if the file exists
    if songs_json_path:
        # Read the content of the file
        with open(songs_json_path, "r") as file:
            songs_data = json.load(file)
        # Return the content as JSONResponse
        return JSONResponse(content=songs_data)
    else:
        # If the file doesn't exist, raise an HTTPException
        raise HTTPException(status_code=404, detail="Songs file not found")
class SongInput(BaseModel):
    title: str
    artist: str

class Song(BaseModel):
    id: int
    title: str
    artist: str
    duration: str
    liked: bool = False

DATA_FILE = Path("data/songs.json")

def load_songs() -> List[dict]:
    if DATA_FILE.exists():
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return []

def save_songs(songs: List[dict]):
    with open(DATA_FILE, "w") as file:
        json.dump(songs, file, indent=4)

@app.post("/addsong", response_model=Song)
async def add_song(song_input: SongInput):
    songs = load_songs()

    # Check if a song with the same title and artist already exists
    if any(song['title'] == song_input.title and song['artist'] == song_input.artist for song in songs):
        raise HTTPException(status_code=400, detail="Song with same title and artist already exists")

    # Generate a random duration for the song (e.g., "2:45")
    duration_minutes = random.randint(1, 5)  # Generate a random number of minutes
    duration_seconds = random.randint(0, 59)  # Generate a random number of seconds
    duration = f"{duration_minutes}:{duration_seconds:02}"  # Format as MM:SS

    # Generate a new id
    new_id = max([song["id"] for song in songs], default=0) + 1

    # Create a new song dictionary with the provided songname, songartist, and generated duration
    new_song = {
        "id": new_id,
        "title": song_input.title,
        "artist": song_input.artist,
        "duration": duration,
        "liked": False
    }

    # Append the new song to the songs list
    songs.append(new_song)

    # Save the updated songs list to the JSON file
    save_songs(songs)

    # Return the newly created song
    return new_song

@app.delete("/deletesong", response_model=dict)
async def delete_song(song_input: SongInput):
    songs = load_songs()
    song_to_delete = None

    # Find the song in the list
    for song in songs:
        if song["title"] == song_input.title and song["artist"] == song_input.artist:
            song_to_delete = song
            break

    if not song_to_delete:
        raise HTTPException(status_code=404, detail="Song not found")
        

    # Remove the song from the list
    songs.remove(song_to_delete)

    # Save the updated songs list to the JSON file
    save_songs(songs)

    # Return a success message
    return {"message": "Song deleted successfully"}