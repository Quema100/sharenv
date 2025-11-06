window.onload = () => {
    const themeToggleBtn = document.getElementById('themeToggle');
    const currentTheme = localStorage.getItem('securEnvTheme');

    if (currentTheme === 'light') {
        document.body.classList.add('light-mode');
        themeToggleBtn.textContent = '☀';
    }

    themeToggleBtn.addEventListener('click', () => {
        document.body.classList.toggle('light-mode');
        let theme = 'dark';
        if (document.body.classList.contains('light-mode')) {
            theme = 'light';
            themeToggleBtn.textContent = '☀'; 
        } else {
            themeToggleBtn.textContent = '☼'; 
        }
        localStorage.setItem('securEnvTheme', theme); // 선택 저장
    });
}