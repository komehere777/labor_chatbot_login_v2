window.addEventListener('DOMContentLoaded', event => {
    // Chatbot functionality
    const sendBtn = document.getElementById('send-btn');
    const userInput = document.getElementById('user-input');
    const chatWindow = document.getElementById('chat-window');

    // Toggle the side navigation
    const sidebarToggle = document.body.querySelector('#sidebarToggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', event => {
            event.preventDefault();
            document.body.classList.toggle('sb-sidenav-toggled');
            localStorage.setItem('sb|sidebar-toggle', document.body.classList.contains('sb-sidenav-toggled'));
        });
    }

    function addMessageToChat(message, isUser = false) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message');
        if (isUser) {
            messageElement.classList.add('user-message');
        } else {
            messageElement.classList.add('ai-message');
        }

        // innerHTML을 사용하여 HTML 태그를 포함한 메시지를 처리
        messageElement.innerHTML = message;
        chatWindow.appendChild(messageElement);
        chatWindow.scrollTop = chatWindow.scrollHeight;
    }

    sendBtn.addEventListener('click', function() {
        const message = userInput.value;
        if (message.trim() === "") return;

        // 유저의 메시지를 채팅 창에 추가
        addMessageToChat(message, true);
        userInput.value = "";

        // 서버로 메시지 보내기
        fetch('/get_response', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ message: message }),
            credentials: 'same-origin'
        })
        .then(response => {
            if (response.status === 401) {
                // 인증되지 않은 경우
                window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
                throw new Error('Unauthorized');
            }
            return response.json();
        })
        .then(data => {
            // 서버로부터 응답을 받아 AI의 메시지를 채팅 창에 추가
            addMessageToChat(data.response);
        })
        .catch(error => {
            if (error.message !== 'Unauthorized') {
                console.error('Error:', error);
            }
        });
    });

    userInput.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            sendBtn.click();
        }
    });
});