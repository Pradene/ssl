NAME     = ft_ssl
CC       = cc
CFLAGS   = -Wall -Wextra -Werror -g -I.

SRCS_DIR = src
OBJS_DIR = obj
TEST_DIR = test

SRCS      = $(wildcard $(SRCS_DIR)/*.c)
OBJS      = $(patsubst $(SRCS_DIR)/%.c,$(OBJS_DIR)/%.o,$(SRCS))

all: $(NAME)
	@echo "\033[1;32m[OK]\033[0m Build complete: $(NAME)"

$(NAME): $(OBJS)
	@echo "\033[1;34m[LINK]\033[0m Creating executable: $(NAME)"
	@$(CC) $(CFLAGS) $(OBJS) -o $(NAME)

$(OBJS_DIR)/%.o: $(SRCS_DIR)/%.c
	@mkdir -p $(OBJS_DIR)
	@echo "\033[1;36m[CC]\033[0m $<"
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "\033[1;31m[CLEAN]\033[0m Removing object files"
	@rm -rf $(OBJS_DIR)

fclean: clean
	@echo "\033[1;31m[FCLEAN]\033[0m Removing binaries"
	@rm -f $(NAME) $(LINK) $(TEST_BINS)

re: fclean all

.PHONY: all clean fclean re

