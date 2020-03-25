(function($) {
  Craft.CognitoLoginForm = Garnish.Base.extend(
  {
    $form: null,
    $buttons: null,

    init: function(cognitoProvider, error)
    {
      this.$form = $('#login-form');
      this.$submitBtn = $('#submit');
      this.$buttons = $('> .buttons', this.$form);

      $(
        '<a id="linkCognito" href="' + cognitoProvider.url + '">' +
          '<input id="submitCognito" class="btn submit" type="button" value="' + cognitoProvider.text + '">' +
        '</a>'
      ).appendTo(this.$buttons);

      this.addListener(this.$submitBtn, 'click', $.proxy(function() {
        if (this.$error)
        {
          this.$error.remove();
        }
      }, this));

      if (error)
      {
        this.showError(error);
      }
    },

    showError: function(error)
    {
      if (!error)
      {
        error = Craft.t('An unknown error occurred.');
      }

      this.$error = $('<p class="error" style="display:none">'+error+'</p>').insertAfter($('.buttons', this.$form));
      this.$error.velocity('fadeIn');
    },
  });
})(jQuery);
