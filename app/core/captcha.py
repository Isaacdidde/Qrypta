import random


class CaptchaService:
    """
    Generates and validates simple math-based CAPTCHA.
    """

    def __init__(self):
        self.num1 = random.randint(1, 10)
        self.num2 = random.randint(1, 10)
        self.operator = random.choice(["+", "-"])

    def question(self) -> str:
        return f"{self.num1} {self.operator} {self.num2}"

    def answer(self) -> int:
        if self.operator == "+":
            return self.num1 + self.num2
        return self.num1 - self.num2

    def validate(self, user_answer: int) -> bool:
        try:
            return int(user_answer) == self.answer()
        except (ValueError, TypeError):
            return False
