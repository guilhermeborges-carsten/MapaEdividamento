// Função para formatar valores monetários
function formatCurrency(value) {
    return new Intl.NumberFormat('pt-BR', { 
        style: 'currency', 
        currency: 'BRL' 
    }).format(value);
}

// Função para formatar porcentagens
function formatPercentage(value) {
    return new Intl.NumberFormat('pt-BR', { 
        style: 'percent', 
        minimumFractionDigits: 2 
    }).format(value / 100);
}

// Máscaras para campos de formulário
document.addEventListener('DOMContentLoaded', function() {
    // Máscara para valores monetários
    const currencyInputs = document.querySelectorAll('input[type="number"][step="0.01"]');
    currencyInputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.value) {
                this.value = parseFloat(this.value).toFixed(2);
            }
        });
    });

    // Máscara para porcentagens
    const percentageInputs = document.querySelectorAll('input[type="number"][step="0.0001"]');
    percentageInputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.value) {
                this.value = parseFloat(this.value).toFixed(4);
            }
        });
    });

    // Máscara para campos de moeda (formato brasileiro)
    const moneyInputs = document.querySelectorAll('input.money');
    moneyInputs.forEach(input => {
        input.addEventListener('input', function(e) {
            let v = this.value.replace(/\D/g, '');
            v = (v/100).toFixed(2) + '';
            v = v.replace('.', ',');
            v = v.replace(/(\d)(?=(\d{3})+(?!\d))/g, '$1.');
            this.value = v;
        });
        input.addEventListener('blur', function(e) {
            if (this.value && !this.value.includes(',')) {
                this.value = parseFloat(this.value.replace(/\./g, '').replace(',', '.')).toLocaleString('pt-BR', {minimumFractionDigits: 2, maximumFractionDigits: 2});
            }
        });
    });

    // Cálculo automático de campos relacionados
    const saldoInicialInput = document.getElementById('saldo_inicial');
    const principalPendenteInput = document.getElementById('principal_pendente');
    
    if (saldoInicialInput && principalPendenteInput) {
        saldoInicialInput.addEventListener('change', function() {
            if (!principalPendenteInput.value || principalPendenteInput.value === "0") {
                principalPendenteInput.value = this.value;
            }
        });
    }

    // Cálculo de parcelas pendentes
    const qtdParcelaInput = document.getElementById('qtd_parcela');
    const parcPagaInput = document.getElementById('parc_paga');
    const parcPendenteInput = document.getElementById('parc_pendente');
    
    if (qtdParcelaInput && parcPagaInput && parcPendenteInput) {
        qtdParcelaInput.addEventListener('change', updateParcelasPendentes);
        parcPagaInput.addEventListener('change', updateParcelasPendentes);
        
        function updateParcelasPendentes() {
            if (qtdParcelaInput.value && parcPagaInput.value) {
                parcPendenteInput.value = parseInt(qtdParcelaInput.value) - parseInt(parcPagaInput.value);
            }
        }
    }

    // Tooltips do Bootstrap
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Popovers do Bootstrap
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Validação de formulário e conversão de moeda ao submeter
    const forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function() {
            const camposValor = form.querySelectorAll('input.valor');
            camposValor.forEach(function(campo) {
                if (campo.value) {
                    // Se for campo de taxa (juros), só troca vírgula por ponto
                    if (campo.name.includes('juros')) {
                        campo.value = campo.value.replace(',', '.');
                    } else {
                        campo.value = campo.value.replace(/\./g, '').replace(',', '.');
                    }
                }
            });
            // Validação padrão
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // Fechar alertas automaticamente
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.classList.add('fade');
            setTimeout(() => alert.remove(), 150);
        }, 5000);
    });

    // Preencher taxa do indexador automaticamente
    const indexadorSelect = document.getElementById('indexador');
    const jurosMensalInput = document.getElementById('juros_mensal');
    if (indexadorSelect && jurosMensalInput) {
        indexadorSelect.addEventListener('change', function() {
            const indexador = this.value;
            if (indexador) {
                fetch(`/taxa_indexador/${indexador}`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.taxa) {
                            // Converter taxa para formato brasileiro se necessário
                            let taxa = data.taxa.replace('.', ',');
                            jurosMensalInput.value = taxa;
                        }
                    });
            }
        });
    }
});

// Funções para os gráficos (usando Chart.js)
function initCharts() {
    // Gráfico de distribuição por instituição
    const instituicaoCtx = document.getElementById('instituicaoChart');
    if (instituicaoCtx) {
        new Chart(instituicaoCtx, {
            type: 'bar',
            data: {
                labels: JSON.parse(instituicaoCtx.dataset.labels || '[]'),
                datasets: [{
                    label: 'Valor Total',
                    data: JSON.parse(instituicaoCtx.dataset.data || '[]'),
                    backgroundColor: [
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(255, 159, 64, 0.7)',
                        'rgba(153, 102, 255, 0.7)'
                    ],
                    borderColor: [
                        'rgba(54, 162, 235, 1)',
                        'rgba(255, 99, 132, 1)',
                        'rgba(75, 192, 192, 1)',
                        'rgba(255, 159, 64, 1)',
                        'rgba(153, 102, 255, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return formatCurrency(context.raw);
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {
                                return formatCurrency(value);
                            }
                        }
                    }
                }
            }
        });
    }

    // Gráfico de distribuição por indexador
    const indexadorCtx = document.getElementById('indexadorChart');
    if (indexadorCtx) {
        new Chart(indexadorCtx, {
            type: 'pie',
            data: {
                labels: JSON.parse(indexadorCtx.dataset.labels || '[]'),
                datasets: [{
                    data: JSON.parse(indexadorCtx.dataset.data || '[]'),
                    backgroundColor: [
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(255, 206, 86, 0.7)'
                    ],
                    borderColor: '#fff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'right' },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${formatCurrency(value)} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }
}

// Inicializar gráficos quando o DOM estiver pronto
document.addEventListener('DOMContentLoaded', initCharts);

// Função para confirmar exclusões
function confirmDelete(event) {
    event.preventDefault();
    const url = event.currentTarget.getAttribute('href');
    
    Swal.fire({
        title: 'Tem certeza?',
        text: "Você não poderá reverter isso!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: 'Sim, excluir!',
        cancelButtonText: 'Cancelar'
    }).then((result) => {
        if (result.isConfirmed) {
            window.location.href = url;
        }
    });
}

// Adicionar eventos de confirmação para botões de exclusão
document.querySelectorAll('.btn-delete').forEach(button => {
    button.addEventListener('click', confirmDelete);
});

$(document).ready(function() {
    // Autocomplete bancos para cadastro
    $('#instituicao').on('input', function() {
        var query = $(this).val();
        if (query.length < 2) {
            $('#autocomplete-bancos').empty();
            return;
        }
        $.getJSON('/bancos_bcb', function(data) {
            var results = data.filter(function(banco) {
                return banco.nome.toLowerCase().includes(query.toLowerCase()) || banco.codigo.includes(query);
            });
            var html = '';
            results.slice(0, 10).forEach(function(banco) {
                html += '<a href="#" class="list-group-item list-group-item-action banco-item" data-codigo="' + banco.codigo + '" data-nome="' + banco.nome + '">' + banco.codigo + ' - ' + banco.nome + '</a>';
            });
            $('#autocomplete-bancos').html(html).show();
        });
    });
    $(document).on('click', '.banco-item', function(e) {
        e.preventDefault();
        $('#instituicao').val($(this).data('nome'));
        $('#autocomplete-bancos').empty();
    });
    $(document).click(function(e) {
        if (!$(e.target).closest('#instituicao, #autocomplete-bancos').length) {
            $('#autocomplete-bancos').empty();
        }
    });
    // Autocomplete bancos para filtro do index
    $('#instituicao_filtro').on('input', function() {
        var query = $(this).val();
        console.log('Digitando no filtro de instituição:', query); // DEBUG
        if (query.length < 2) {
            $('#autocomplete-bancos-filtro').empty();
            return;
        }
        $.getJSON('/bancos_bcb', function(data) {
            console.log('Resposta do /bancos_bcb:', data); // DEBUG
            var results = data.filter(function(banco) {
                return banco.nome.toLowerCase().includes(query.toLowerCase()) || banco.codigo.includes(query);
            });
            var html = '';
            results.slice(0, 10).forEach(function(banco) {
                html += '<a href="#" class="list-group-item list-group-item-action banco-item-filtro" data-codigo="' + banco.codigo + '" data-nome="' + banco.nome + '">' + banco.codigo + ' - ' + banco.nome + '</a>';
            });
            $('#autocomplete-bancos-filtro').html(html).show();
        });
    });
    $(document).on('click', '.banco-item-filtro', function(e) {
        e.preventDefault();
        $('#instituicao_filtro').val($(this).data('nome'));
        $('#autocomplete-bancos-filtro').empty();
    });
    $(document).click(function(e) {
        if (!$(e.target).closest('#instituicao_filtro, #autocomplete-bancos-filtro').length) {
            $('#autocomplete-bancos-filtro').empty();
        }
    });
    // Regras condicionais Modalidade
    function updateFields() {
        var modalidade = $('#modalidade').val();
        if (modalidade === 'pre') {
            $('#spread').prop('disabled', true);
            $('#juros_mensal').prop('disabled', false);
        } else if (modalidade === 'pos') {
            $('#spread').prop('disabled', false);
            $('#juros_mensal').prop('disabled', true);
        } else {
            $('#spread').prop('disabled', false);
            $('#juros_mensal').prop('disabled', false);
        }
    }
    $('#modalidade').on('change', updateFields);
    updateFields();
    // Garantir que campos de output sejam readonly
    $("input[readonly]").on('keydown paste', function(e) {
        e.preventDefault();
    });
});