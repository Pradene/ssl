NAME     = ft_ssl
CC       = cc
CFLAGS   = -Wall -Wextra -Werror -g -I. -I./libft/inc/

SRCS_DIR = src
OBJS_DIR = obj

SRCS      = $(wildcard $(SRCS_DIR)/*.c)
OBJS      = $(patsubst $(SRCS_DIR)/%.c,$(OBJS_DIR)/%.o,$(SRCS))

LIBFT_DIR = libft
LIBFT = libft.a

all: $(NAME)
	@echo "\033[1;32m[OK]\033[0m Build complete: $(NAME)"

$(LIBFT):
	@$(MAKE) -C $(LIBFT_DIR)

$(NAME): $(LIBFT) $(OBJS)
	@echo "\033[1;34m[LINK]\033[0m Creating executable: $(NAME)"
	@$(CC) $(CFLAGS) $(OBJS) $(LIBFT_DIR)/$(LIBFT) -o $(NAME)

$(OBJS_DIR)/%.o: $(SRCS_DIR)/%.c
	@mkdir -p $(OBJS_DIR)
	@echo "\033[1;36m[CC]\033[0m $<"
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "\033[1;31m[CLEAN]\033[0m Removing object files"
	@rm -rf $(OBJS_DIR)
	@$(MAKE) -C $(LIBFT_DIR) clean

fclean: clean
	@echo "\033[1;31m[FCLEAN]\033[0m Removing binaries"
	@rm -f $(NAME)
	@$(MAKE) -C $(LIBFT_DIR) fclean

re: fclean all

.PHONY: all clean fclean re

