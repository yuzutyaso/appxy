import React, { useState, useEffect, createContext, useContext, useRef } from 'react';

// --- 1. グローバルな状態管理 (AuthContext) ---
const AuthContext = createContext(null);

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null); // { id, username, user_identifier }
  const [token, setToken] = useState(null); // 簡易認証のためダミートークンを使用
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // ローカルストレージからユーザー情報をロード (リロード時にセッションを維持)
    const storedUser = localStorage.getItem('user');
    const storedToken = localStorage.getItem('token');
    if (storedUser && storedToken) {
      try {
        setUser(JSON.parse(storedUser));
        setToken(storedToken);
      } catch (e) {
        console.error("Failed to parse user from localStorage", e);
        localStorage.clear(); // 無効なデータがあればクリア
      }
    }
    setIsLoading(false);
  }, []);

  const login = (userData, userToken) => {
    setUser(userData);
    setToken(userToken);
    localStorage.setItem('user', JSON.stringify(userData));
    localStorage.setItem('token', userToken);
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('user');
    localStorage.removeItem('token');
  };

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated: !!user, login, logout, isLoading }}>
      {children}
    </AuthContext.Provider>
  );
};

// --- 2. APIサービス ---
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const WS_BASE_URL = API_BASE_URL.replace('http', 'ws');

const api = {
  // ユーザー登録
  register: async (username, password) => {
    const response = await fetch(`${API_BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Registration failed');
    }
    return response.json();
  },
  // ログイン
  login: async (username, password) => {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);

    const response = await fetch(`${API_BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Login failed');
    }
    return response.json();
  },
  // ユーザー検索
  searchUser: async (identifier, token) => {
    // 簡易認証のため、usernameとpasswordをBearerトークンとして送信
    const user = JSON.parse(localStorage.getItem('user'));
    const password = JSON.parse(localStorage.getItem('temp_password')); // 登録/ログイン時に一時保存したパスワード
    const headers = new Headers();
    headers.append('Content-Type', 'application/json');
    headers.append('Authorization', `Bearer username="${user.username}",password="${password}"`);

    const response = await fetch(`${API_BASE_URL}/users/search/${identifier}`, {
      headers: headers
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'User search failed');
    }
    return response.json();
  },
  // 友達追加
  addFriend: async (friendIdentifier, token) => {
    const user = JSON.parse(localStorage.getItem('user'));
    const password = JSON.parse(localStorage.getItem('temp_password'));
    const headers = new Headers();
    headers.append('Content-Type', 'application/json');
    headers.append('Authorization', `Bearer username="${user.username}",password="${password}"`);

    const response = await fetch(`${API_BASE_URL}/friends/add`, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ friend_identifier: friendIdentifier }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Add friend failed');
    }
    return response.json();
  },
  // 友達リスト取得
  getFriends: async (token) => {
    const user = JSON.parse(localStorage.getItem('user'));
    const password = JSON.parse(localStorage.getItem('temp_password'));
    const headers = new Headers();
    headers.append('Content-Type', 'application/json');
    headers.append('Authorization', `Bearer username="${user.username}",password="${password}"`);

    const response = await fetch(`${API_BASE_URL}/friends`, {
      headers: headers
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Failed to fetch friends');
    }
    return response.json();
  },
};

// --- 3. 認証フォームコンポーネント ---
const AuthForm = ({ type, onAuthSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useContext(AuthContext);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      let response;
      if (type === 'register') {
        response = await api.register(username, password);
        alert(`登録成功！あなたのユーザーID: ${response.user_identifier}`);
        // 登録後、自動ログインを試みる
        const loginResponse = await api.login(username, password);
        login(loginResponse, 'dummy-token'); // 簡易認証なのでダミートークン
        localStorage.setItem('temp_password', JSON.stringify(password)); // 簡易認証のためパスワードを一時保存
      } else { // login
        response = await api.login(username, password);
        login(response, 'dummy-token'); // 簡易認証なのでダミートークン
        localStorage.setItem('temp_password', JSON.stringify(password)); // 簡易認証のためパスワードを一時保存
      }
      onAuthSuccess();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="auth-container">
      <h2>{type === 'register' ? 'アカウント作成' : 'ログイン'}</h2>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>ユーザー名:</label>
          <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </div>
        <div className="form-group">
          <label>パスワード:</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>
        {error && <p className="error-message">{error}</p>}
        <button type="submit">{type === 'register' ? '登録' : 'ログイン'}</button>
      </form>
    </div>
  );
};

// --- 4. ダッシュボードコンポーネント ---
const Dashboard = ({ onSelectChat }) => {
  const { user, logout, token } = useContext(AuthContext);
  const [searchId, setSearchId] = useState('');
  const [searchResult, setSearchResult] = useState(null);
  const [searchError, setSearchError] = useState('');
  const [friends, setFriends] = useState([]);
  const [friendsError, setFriendsError] = useState('');

  const fetchFriends = async () => {
    try {
      const friendList = await api.getFriends(token);
      setFriends(friendList);
      setFriendsError('');
    } catch (err) {
      setFriendsError(err.message);
    }
  };

  useEffect(() => {
    if (token) {
      fetchFriends();
    }
  }, [token]);

  const handleSearch = async (e) => {
    e.preventDefault();
    setSearchResult(null);
    setSearchError('');
    try {
      const result = await api.searchUser(searchId, token);
      setSearchResult(result);
    } catch (err) {
      setSearchError(err.message);
    }
  };

  const handleAddFriend = async (friendIdentifier) => {
    try {
      await api.addFriend(friendIdentifier, token);
      alert('友達を追加しました！');
      await fetchFriends(); // 友達リストを更新
      setSearchResult(null); // 検索結果をクリア
      setSearchId(''); // 検索IDをクリア
    } catch (err) {
      setSearchError(err.message);
    }
  };

  return (
    <div className="dashboard-container">
      <h1>ようこそ、{user?.username}さん！</h1>
      <p>あなたのユーザーID: <strong>{user?.user_identifier}</strong></p>
      <button onClick={logout} className="logout-button">ログアウト</button>

      <hr />

      <h3>友達を検索・追加</h3>
      <form onSubmit={handleSearch} className="search-form">
        <input
          type="text"
          placeholder="ユーザーIDで検索"
          value={searchId}
          onChange={(e) => setSearchId(e.target.value)}
          required
        />
        <button type="submit">検索</button>
      </form>
      {searchError && <p className="error-message">{searchError}</p>}
      {searchResult && (
        <div className="search-result">
          <p>見つかりました: {searchResult.username} ({searchResult.user_identifier})</p>
          {searchResult.id !== user.id && ( // 自分自身は追加できない
            <button onClick={() => handleAddFriend(searchResult.user_identifier)}>友達追加</button>
          )}
        </div>
      )}

      <hr />

      <h3>友達リスト</h3>
      {friendsError && <p className="error-message">{friendsError}</p>}
      {friends.length === 0 ? (
        <p>まだ友達がいません。</p>
      ) : (
        <ul className="friend-list">
          {friends.map((friend) => (
            <li key={friend.id} onClick={() => onSelectChat(friend)}>
              {friend.username} ({friend.user_identifier})
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

// --- 5. チャットインターフェースコンポーネント ---
const ChatInterface = ({ selectedFriend, onBackToDashboard }) => {
  const { user } = useContext(AuthContext);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const websocketRef = useRef(null);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    if (!user || !selectedFriend) return;

    const wsUrl = `${WS_BASE_URL}/ws/${user.id}`;
    websocketRef.current = new WebSocket(wsUrl);

    websocketRef.current.onopen = () => {
      console.log('WebSocket connected');
    };

    websocketRef.current.onmessage = (event) => {
      const receivedMessage = JSON.parse(event.data);
      // 自分宛のメッセージ、または自分が送ったメッセージのみ表示
      if (
        (receivedMessage.sender_id === user.id && receivedMessage.receiver_id === selectedFriend.id) ||
        (receivedMessage.sender_id === selectedFriend.id && receivedMessage.receiver_id === user.id)
      ) {
        setMessages((prevMessages) => [...prevMessages, receivedMessage]);
      }
    };

    websocketRef.current.onclose = () => {
      console.log('WebSocket disconnected');
    };

    websocketRef.current.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    return () => {
      if (websocketRef.current) {
        websocketRef.current.close();
      }
    };
  }, [user, selectedFriend]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = () => {
    if (newMessage.trim() === '' || !websocketRef.current || websocketRef.current.readyState !== WebSocket.OPEN) {
      return;
    }
    const messageToSend = {
      receiver_identifier: selectedFriend.user_identifier,
      content: newMessage,
    };
    websocketRef.current.send(JSON.stringify(messageToSend));
    setNewMessage('');
  };

  return (
    <div className="chat-container">
      <div className="chat-header">
        <button onClick={onBackToDashboard} className="back-button">← 戻る</button>
        <h2>{selectedFriend.username} ({selectedFriend.user_identifier}) とのチャット</h2>
      </div>
      <div className="message-list">
        {messages.map((msg, index) => (
          <div key={index} className={`message-bubble ${msg.sender_id === user.id ? 'sent' : 'received'}`}>
            <p>{msg.content}</p>
            <span className="timestamp">{new Date(msg.timestamp).toLocaleTimeString()}</span>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>
      <div className="message-input-area">
        <input
          type="text"
          value={newMessage}
          onChange={(e) => setNewMessage(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
          placeholder="メッセージを入力..."
        />
        <button onClick={sendMessage}>送信</button>
      </div>
    </div>
  );
};

// --- 6. メインアプリケーションコンポーネント ---
const App = () => {
  const { isAuthenticated, isLoading } = useContext(AuthContext);
  const [currentPage, setCurrentPage] = useState('login'); // 'login', 'register', 'dashboard', 'chat'
  const [selectedFriend, setSelectedFriend] = useState(null);

  useEffect(() => {
    if (isLoading) return;
    if (isAuthenticated) {
      setCurrentPage('dashboard');
    } else {
      setCurrentPage('login');
    }
  }, [isAuthenticated, isLoading]);

  const handleAuthSuccess = () => {
    setCurrentPage('dashboard');
  };

  const handleSelectChat = (friend) => {
    setSelectedFriend(friend);
    setCurrentPage('chat');
  };

  const handleBackToDashboard = () => {
    setSelectedFriend(null);
    setCurrentPage('dashboard');
  };

  if (isLoading) {
    return <div className="loading-screen">Loading...</div>;
  }

  return (
    <div className="app-container">
      {currentPage === 'login' && <AuthForm type="login" onAuthSuccess={handleAuthSuccess} />}
      {currentPage === 'register' && <AuthForm type="register" onAuthSuccess={handleAuthSuccess} />}
      {currentPage === 'dashboard' && isAuthenticated && <Dashboard onSelectChat={handleSelectChat} />}
      {currentPage === 'chat' && isAuthenticated && selectedFriend && (
        <ChatInterface selectedFriend={selectedFriend} onBackToDashboard={handleBackToDashboard} />
      )}
      {!isAuthenticated && currentPage !== 'login' && currentPage !== 'register' && (
        <button onClick={() => setCurrentPage('login')}>ログインページへ</button>
      )}
      {/* 登録ページへの切り替えボタン */}
      {currentPage === 'login' && (
        <p className="toggle-auth">
          アカウントをお持ちではありませんか？ <span onClick={() => setCurrentPage('register')}>登録はこちら</span>
        </p>
      )}
      {currentPage === 'register' && (
        <p className="toggle-auth">
          すでにアカウントをお持ちですか？ <span onClick={() => setCurrentPage('login')}>ログインはこちら</span>
        </p>
      )}
    </div>
  );
};

// AuthProvider で App をラップ
const WrappedApp = () => (
  <AuthProvider>
    <App />
  </AuthProvider>
);

export default WrappedApp;
